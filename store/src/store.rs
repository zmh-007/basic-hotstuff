
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Sender, Receiver};
use tokio::sync::oneshot;
use rocksdb::{DB, Options, ColumnFamilyDescriptor, Error};
use anyhow::Result;

pub type StoreError = Error;
type StoreResult<T> = Result<T, StoreError>;

type Value = Vec<u8>;

// Column family name
const CONSENSUS_CF: &str = "consensus";

// Core consensus state keys
const VOTED_NODE_KEY: &[u8] = b"voted_node";
const PREPARE_QC_KEY: &[u8] = b"prepare_qc";
const LOCK_QC_KEY: &[u8] = b"lock_qc";
const LOCK_BLOB_KEY: &[u8] = b"lock_blob";

pub enum StoreCommand {
    // Core consensus state commands
    WriteVotedNode(Value),
    WritePrepareQC(Value),
    WriteLockQC(Value),
    WriteLockBlob(String),
    
    // Core consensus state read commands
    ReadVotedNode(oneshot::Sender<StoreResult<Option<Value>>>),
    ReadPrepareQC(oneshot::Sender<StoreResult<Option<Value>>>),
    ReadLockQC(oneshot::Sender<StoreResult<Option<Value>>>),
    ReadLockBlob(oneshot::Sender<StoreResult<Option<Value>>>),
}

#[derive(Clone)]
pub struct Store {
    channel: Sender<StoreCommand>,
}

impl Store {
    pub fn new(path: &str) -> StoreResult<Self> {
        let db = Self::create_database(path)?;
        let (tx, rx) = channel(100);
        
        tokio::spawn(Self::process_commands(rx, db));
        Ok(Self { channel: tx })
    }
    
    fn create_database(path: &str) -> StoreResult<Arc<DB>> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        
        let cf_descriptor = ColumnFamilyDescriptor::new(CONSENSUS_CF, Options::default());
            
        Ok(Arc::new(DB::open_cf_descriptors(&opts, path, vec![cf_descriptor])?))
    }

    async fn process_commands(
        mut rx: Receiver<StoreCommand>,
        db: Arc<DB>,
    ) {

        while let Some(command) = rx.recv().await {
            let consensus_cf = db.cf_handle(CONSENSUS_CF).unwrap();

            match command {
                StoreCommand::WriteVotedNode(value) => {
                    let _ = db.put_cf(&consensus_cf, VOTED_NODE_KEY, &value);
                }
                StoreCommand::WritePrepareQC(value) => {
                    let _ = db.put_cf(&consensus_cf, PREPARE_QC_KEY, &value);
                }
                StoreCommand::WriteLockQC(value) => {
                    let _ = db.put_cf(&consensus_cf, LOCK_QC_KEY, &value);
                }
                StoreCommand::WriteLockBlob(value) => {
                    let value_bytes = value.as_bytes().to_vec();
                    let _ = db.put_cf(&consensus_cf, LOCK_BLOB_KEY, &value_bytes);
                }
                StoreCommand::ReadVotedNode(sender) => {
                    let response = db.get_cf(&consensus_cf, VOTED_NODE_KEY);
                    let _ = sender.send(response);
                }
                StoreCommand::ReadPrepareQC(sender) => {
                    let response = db.get_cf(&consensus_cf, PREPARE_QC_KEY);
                    let _ = sender.send(response);
                }
                StoreCommand::ReadLockQC(sender) => {
                    let response = db.get_cf(&consensus_cf, LOCK_QC_KEY);
                    let _ = sender.send(response);
                }
                StoreCommand::ReadLockBlob(sender) => {
                    let response = db.get_cf(&consensus_cf, LOCK_BLOB_KEY);
                    let _ = sender.send(response);
                }
            }
        }
    }

    // Core consensus state write methods
    pub async fn write_voted_node(&mut self, value: Value) {
        if let Err(e) = self.channel.send(StoreCommand::WriteVotedNode(value)).await {
            panic!("Failed to send Write VotedNode command to store: {}", e);
        }
    }
    
    pub async fn write_prepare_qc(&mut self, value: Value) {
        if let Err(e) = self.channel.send(StoreCommand::WritePrepareQC(value)).await {
            panic!("Failed to send Write PrepareQC command to store: {}", e);
        }
    }
    
    pub async fn write_lock_qc(&mut self, value: Value) {
        if let Err(e) = self.channel.send(StoreCommand::WriteLockQC(value)).await {
            panic!("Failed to send Write LockQC command to store: {}", e);
        }
    }
    
    pub async fn write_lock_blob(&mut self, value: String) {
        if let Err(e) = self.channel.send(StoreCommand::WriteLockBlob(value)).await {
            panic!("Failed to send Write LockBlob command to store: {}", e);
        }
    }
    // Core consensus state read methods
    pub async fn read_voted_node(&mut self) -> StoreResult<Option<Value>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self.channel.send(StoreCommand::ReadVotedNode(sender)).await {
            panic!("Failed to send Read VotedNode command to store: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive reply to Read VotedNode command from store")
    }
    
    pub async fn read_prepare_qc(&mut self) -> StoreResult<Option<Value>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self.channel.send(StoreCommand::ReadPrepareQC(sender)).await {
            panic!("Failed to send Read PrepareQC command to store: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive reply to Read PrepareQC command from store")
    }
    
    pub async fn read_lock_qc(&mut self) -> StoreResult<Option<Value>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self.channel.send(StoreCommand::ReadLockQC(sender)).await {
            panic!("Failed to send Read LockQC command to store: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive reply to Read LockQC command from store")
    }
    
    pub async fn read_lock_blob(&mut self) -> StoreResult<Option<String>> {
        let (sender, receiver) = oneshot::channel();
        if let Err(e) = self.channel.send(StoreCommand::ReadLockBlob(sender)).await {
            panic!("Failed to send Read LockBlob command to store: {}", e);
        }
        let result = receiver
            .await
            .expect("Failed to receive reply to Read LockBlob command from store");
        
        result.map(|opt| {
            opt.map(|bytes| {
                String::from_utf8(bytes).unwrap_or_default()
            })
        })
    }
}
