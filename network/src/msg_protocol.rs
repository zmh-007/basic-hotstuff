use libp2p::request_response::{Config, Event as RequestResponseEvent, Message as RequestResponseMessage, ProtocolSupport};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{PeerId, StreamProtocol};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use crate::error::{P2pError, P2pResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsgRequest {
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum MsgEvent {
    MessageReceived { payload: Vec<u8> },
    MessageSent { success: bool },
}

type MsgCodec = libp2p::request_response::cbor::Behaviour<MsgRequest, ()>;
type OnMsgCallback = Arc<dyn Fn(PeerId, Vec<u8>) + Sync + Send>;

pub struct MsgProtocol {
    request_response: MsgCodec,
    on_msg_callback: Option<OnMsgCallback>,
    connected_peers: HashSet<PeerId>, // Track connected peers for broadcasting
}

impl MsgProtocol {
    pub fn new_with_callback(on_msg: impl Fn(PeerId, Vec<u8>) + Send + Sync + 'static) -> Self {
        let protocol = StreamProtocol::new("/aggregator/1.0.0");
        let config = Config::default();

        Self {
            request_response: libp2p::request_response::cbor::Behaviour::new([(protocol, ProtocolSupport::Full)], config),
            on_msg_callback: Some(Arc::new(on_msg)),
            connected_peers: HashSet::new(),
        }
    }

    pub fn send_message(&mut self, to_id: Option<PeerId>, payload: Vec<u8>) -> P2pResult<()> {
        let msg = MsgRequest { payload };

        if let Some(to) = to_id {
            // Send to specific peer
            if self.connected_peers.contains(&to) {
                self.request_response.send_request(&to, msg);
                Ok(())
            } else {
                Err(P2pError::PeerNotConnected(to.to_string()))
            }
        } else {
            // Broadcast to all connected peers
            if self.connected_peers.is_empty() {
                return Err(P2pError::NoPeersAvailable);
            }

            for peer in &self.connected_peers {
                self.request_response.send_request(peer, msg.clone());
            }
            Ok(())
        }
    }

    fn register_peer(&mut self, peer_id: PeerId) {
        self.connected_peers.insert(peer_id);
    }

    fn unregister_peer(&mut self, peer_id: &PeerId) {
        self.connected_peers.remove(peer_id);
    }
}

impl NetworkBehaviour for MsgProtocol {
    type ConnectionHandler = <MsgCodec as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = MsgEvent;

    fn handle_established_inbound_connection(
        &mut self, _connection_id: libp2p::swarm::ConnectionId, _peer: PeerId, _local_addr: &libp2p::Multiaddr, _remote_addr: &libp2p::Multiaddr,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        // Reject all inbound connections - only allow active outbound connections
        Err(libp2p::swarm::ConnectionDenied::new("This node does not accept inbound connections"))
    }

    fn handle_established_outbound_connection(
        &mut self, connection_id: libp2p::swarm::ConnectionId, peer: PeerId, addr: &libp2p::Multiaddr, role_override: libp2p::core::Endpoint, port_use: libp2p::core::transport::PortUse,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        self.request_response.handle_established_outbound_connection(connection_id, peer, addr, role_override, port_use)
    }

    fn on_swarm_event(&mut self, event: libp2p::swarm::FromSwarm) {
        use libp2p::swarm::FromSwarm::*;
        match &event {
            ConnectionEstablished(e) => { self.register_peer(e.peer_id); }
            ConnectionClosed(e) => { self.unregister_peer(&e.peer_id); }
            _ => {}
        }
        self.request_response.on_swarm_event(event);
    }

    fn on_connection_handler_event(&mut self, peer_id: PeerId, connection_id: libp2p::swarm::ConnectionId, event: libp2p::swarm::THandlerOutEvent<Self>) {
        self.request_response.on_connection_handler_event(peer_id, connection_id, event);
    }

    fn poll(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<libp2p::swarm::ToSwarm<Self::ToSwarm, libp2p::swarm::THandlerInEvent<Self>>> {
        loop {
            match self.request_response.poll(cx) {
                std::task::Poll::Ready(libp2p::swarm::ToSwarm::GenerateEvent(event)) => match event {
                    RequestResponseEvent::Message { peer, message, .. } => match message {
                        RequestResponseMessage::Request { request, channel, .. } => {
                            let _ = self.request_response.send_response(channel, ());
                            
                            // Call callback function with PeerId directly
                            if let Some(callback) = &self.on_msg_callback {
                                callback(peer, request.payload.clone());
                            }

                            return std::task::Poll::Ready(libp2p::swarm::ToSwarm::GenerateEvent(MsgEvent::MessageReceived { payload: request.payload }));
                        }
                        RequestResponseMessage::Response { .. } => {
                            return std::task::Poll::Ready(libp2p::swarm::ToSwarm::GenerateEvent(MsgEvent::MessageSent { success: true }));
                        }
                    },
                    RequestResponseEvent::OutboundFailure { .. } => {
                        return std::task::Poll::Ready(libp2p::swarm::ToSwarm::GenerateEvent(MsgEvent::MessageSent { success: false }));
                    }
                    _ => {}
                },
                std::task::Poll::Ready(other) => return std::task::Poll::Ready(other.map_out(|_| unreachable!())),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}
