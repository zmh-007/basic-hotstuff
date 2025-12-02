// Internal modules
mod config;
mod node;

// External crate imports
use clap::{Parser, Subcommand};
use env_logger::Env;
use log::error;

// Internal imports
use crate::node::Node;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Turn debugging information on.
    #[clap(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// The command to execute.
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new keypair.
    Keys {
        /// The file where to print the new key pair.
        #[clap(short, long, value_parser, value_name = "FILE")]
        filename: String,
    },
    /// Run a single node.
    Run {
        /// The file containing the node keys.
        #[clap(short, long, value_parser, value_name = "FILE")]
        keys: String,
        /// The file containing committee information.
        #[clap(short, long, value_parser, value_name = "FILE")]
        committee: String,
        /// Optional file containing the node parameters.
        #[clap(short, long, value_parser, value_name = "FILE")]
        parameters: Option<String>,
        /// The path where to create the data store.
        #[clap(short, long, value_parser, value_name = "PATH")]
        store: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let log_level = match cli.verbose {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };
    let mut logger = env_logger::Builder::from_env(Env::default().default_filter_or(log_level));
    logger.init();

    match cli.command {
        Command::Keys { filename } => {
            if let Err(e) = Node::print_key_file(&filename) {
                error!("Failed to generate keys: {}", e);
                std::process::exit(1);
            }
        }
        Command::Run {
            keys,
            committee,
            parameters,
            store,
        } => {
            match Node::new(&committee, &keys, &store, parameters).await {
                Ok(mut node) => {
                    node.start().await;
                }
                Err(e) => {
                    error!("Failed to start node: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
