use base64::{engine::general_purpose, Engine as _};
use futures::prelude::*;
use libp2p::{
    identify, identity, noise, ping,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId,
};
use log::{info, warn, debug};
use std::time::Duration;
use tokio::sync::mpsc;
use crate::error::{P2pError, P2pResult};
use crate::msg_protocol::{MsgEvent, MsgProtocol};

#[derive(NetworkBehaviour)]
pub struct P2pBehaviour {
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    msg: MsgProtocol,
}

#[derive(Debug, Clone)]
pub struct P2pConfig {
    pub leader_nodes: Vec<String>,
    pub min_peers: u32,
    pub idle_timeout: Duration,
    pub ping_interval: Duration,
    pub private_key: Option<String>,
    pub enable_reconnect: bool,
    pub reconnect_interval: Duration,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            leader_nodes: env_var_or("LEADER_NODES", String::new()).split(',').filter(|s| !s.is_empty()).map(|s| s.trim().to_string()).collect(),
            min_peers: env_var_or("P2P_MIN_PEERS", 2),
            idle_timeout: Duration::from_secs(env_var_or("P2P_IDLE_TIMEOUT", 600)),
            ping_interval: Duration::from_secs(env_var_or("P2P_PING_INTERVAL", 30)),
            private_key: std::env::var("P2P_PRIVATE_KEY").ok(),
            enable_reconnect: env_var_or("P2P_ENABLE_RECONNECT", true),
            reconnect_interval: Duration::from_secs(env_var_or("P2P_RECONNECT_INTERVAL", 30)),
        }
    }
}

impl P2pConfig {
    pub fn generate_private_key() -> String {
        let keypair = identity::Keypair::generate_ed25519();
        general_purpose::STANDARD.encode(keypair.to_protobuf_encoding().expect("Valid keypair"))
    }

    pub fn with_new_key() -> Self {
        Self { private_key: Some(Self::generate_private_key()), ..Default::default() }
    }
}

#[derive(Debug)]
enum NodeCommand {
    SendMessage(Option<PeerId>, Vec<u8>),
}

struct State {
    local_peer_id: PeerId,
    command_tx: mpsc::UnboundedSender<NodeCommand>,
}

pub struct P2pLibp2p {
    config: P2pConfig,
    state: Option<State>,
}

impl P2pLibp2p {
    pub fn default() -> Self {
        Self::new(P2pConfig::default())
    }
}

impl P2pLibp2p {
    pub fn init(&mut self, on_msg: impl Fn(PeerId, Vec<u8>) + Send + Sync + 'static) -> P2pResult<()> {
        if self.state.is_some() {
            return Err(P2pError::AlreadyInitialized);
        }

        let keypair = self.create_keypair()?;
        let local_peer_id = PeerId::from(keypair.public());
        info!("Using peer ID: {}", local_peer_id);

        let (command_tx, command_rx) = mpsc::unbounded_channel();

        self.state = Some(State { local_peer_id, command_tx });

        self.spawn_event_loop(keypair, command_rx, on_msg);
        Ok(())
    }

    pub fn send(&mut self, to: Option<PeerId>, msg: Vec<u8>) -> P2pResult<()> {
        let state = self.state.as_ref().ok_or(P2pError::NotInitialized)?;
        state.command_tx.send(NodeCommand::SendMessage(to, msg))
            .map_err(|_| P2pError::ChannelClosed)?;
        Ok(())
    }
}

impl P2pLibp2p {
    pub fn new(config: P2pConfig) -> Self {
        Self { config, state: None }
    }

    pub fn get_private_key(&self) -> Option<String> {
        self.config.private_key.clone()
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.state.as_ref().map(|s| s.local_peer_id).expect("Node not initialized")
    }

    pub fn is_initialized(&self) -> bool {
        self.state.is_some()
    }

    fn create_keypair(&self) -> P2pResult<identity::Keypair> {
        if let Some(ref private_key_b64) = self.config.private_key {
            let private_key_bytes = general_purpose::STANDARD.decode(private_key_b64)
                .map_err(|e| P2pError::InvalidPrivateKey(format!("Failed to decode: {}", e)))?;

            identity::Keypair::from_protobuf_encoding(&private_key_bytes)
                .map_err(|e| P2pError::InvalidPrivateKey(format!("Failed to parse: {}", e)))
        } else {
            let new_keypair = identity::Keypair::generate_ed25519();
            let encoded = new_keypair.to_protobuf_encoding()
                .map_err(|e| P2pError::KeypairGeneration(format!("Failed to encode: {}", e)))?;
            info!("Generated new keypair. To reuse this identity, set P2P_PRIVATE_KEY={}", general_purpose::STANDARD.encode(&encoded));
            Ok(new_keypair)
        }
    }

    fn spawn_event_loop(
        &self, keypair: identity::Keypair, mut command_rx: mpsc::UnboundedReceiver<NodeCommand>,
        on_msg: impl Fn(PeerId, Vec<u8>) + Send + Sync + 'static,
    ) {
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut swarm = Self::build_swarm(keypair, &config, on_msg).await;
            Self::connect_to_leader_nodes(&mut swarm, &config.leader_nodes).await;

            // Setup reconnect timer if enabled
            let mut reconnect_timer = if config.enable_reconnect {
                Some(tokio::time::interval(config.reconnect_interval))
            } else {
                None
            };

            if let Some(timer) = &mut reconnect_timer {
                timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            }

            loop {
                tokio::select! {
                    Some(cmd) = command_rx.recv() => {
                        Self::handle_command(&mut swarm, cmd);
                    }
                    _ = async {
                        if let Some(timer) = &mut reconnect_timer {
                            timer.tick().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        // Reconnect logic: try to reconnect to leader nodes if not connected
                        if config.enable_reconnect {
                            Self::try_reconnect_leader_nodes(&mut swarm, &config.leader_nodes).await;
                        }
                    }
                    swarm_event = swarm.select_next_some() => {
                        Self::handle_swarm_event(
                            &mut swarm,
                            swarm_event,
                        ).await;
                    }
                }
            }
        });
    }
    
    async fn build_swarm(keypair: identity::Keypair, config: &P2pConfig, on_msg: impl Fn(PeerId, Vec<u8>) + Send + Sync + 'static) -> libp2p::Swarm<P2pBehaviour> {
        libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)
            .unwrap()
            .with_behaviour(|key| {
                Ok(P2pBehaviour {
                    ping: ping::Behaviour::new(ping::Config::new().with_interval(config.ping_interval)),
                    identify: identify::Behaviour::new(identify::Config::new("/agg-p2p/1.0.0".to_string(), key.public())),
                    msg: MsgProtocol::new_with_callback(on_msg),
                })
            })
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(config.idle_timeout))
            .build()
    }

    async fn connect_to_leader_nodes(swarm: &mut libp2p::Swarm<P2pBehaviour>, leader_nodes: &[String]) {
        if leader_nodes.is_empty() {
            warn!("No leader nodes configured");
            return;
        }

        for leader_addr in leader_nodes {
            if let Ok(addr) = leader_addr.parse::<Multiaddr>() {
                info!("Connecting to leader node: {}", addr);
                if let Err(e) = swarm.dial(addr) {
                    warn!("Failed to dial leader node {}: {}", leader_addr, e);
                }
            } else {
                warn!("Invalid leader address: {}", leader_addr);
            }
        }
    }

    async fn try_reconnect_leader_nodes(swarm: &mut libp2p::Swarm<P2pBehaviour>, leader_nodes: &[String]) {
        if leader_nodes.is_empty() {
            return;
        }

        let connected_count = swarm.connected_peers().count();
        debug!("Reconnect check: connected peers = {}", connected_count);

        // Try to reconnect to leader nodes that are not connected
        for leader_addr in leader_nodes {
            if let Ok(addr) = leader_addr.parse::<Multiaddr>() {
                if let Some(peer_id) = extract_peer_id(&addr) {
                    if !swarm.is_connected(&peer_id) {
                        debug!("Attempting to reconnect to leader node: {} ({})", peer_id, addr);
                        if let Err(e) = swarm.dial(addr) {
                            debug!("Failed to reconnect to leader node {}: {}", leader_addr, e);
                        }
                    }
                }
            }
        }
    }

    fn handle_command(swarm: &mut libp2p::Swarm<P2pBehaviour>, cmd: NodeCommand) {
        match cmd {
            NodeCommand::SendMessage(to, payload) => {
                if let Err(e) = swarm.behaviour_mut().msg.send_message(to, payload) {
                    warn!("Failed to send message: {}", e);
                }
            }
        }
    }

    async fn handle_swarm_event(_swarm: &mut libp2p::Swarm<P2pBehaviour>, event: SwarmEvent<P2pBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {:?}", address);
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!("Connected to peer: {}", peer_id);
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!("Disconnected from peer: {}", peer_id);
            }
            SwarmEvent::Behaviour(P2pBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                debug!("Identified peer {} with {} addresses", peer_id, info.listen_addrs.len());
            }
            SwarmEvent::Behaviour(P2pBehaviourEvent::Msg(MsgEvent::MessageReceived { payload })) => {
                debug!("Message processed successfully, payload size: {} bytes", payload.len());
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(peer) = peer_id {
                    warn!("Failed to connect to {}: {}", peer, error);
                }
            }
            _ => {}
        }
    }


}

fn env_var_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::P2p(id) => Some(id),
        _ => None,
    })
}
