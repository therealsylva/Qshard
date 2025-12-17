use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "qshard")]
#[command(about = "A CLI tool for decentralized credential sharding", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Create {
        #[arg(short, long, default_value = ".", help = "Directory to save shard files")]
        output_dir: PathBuf,

        #[arg(short, long, help = "Optional identifier for the shard set")]
        id: Option<String>,
    },
    Recover {
        #[arg(help = "A path to a shard file or a directory containing shard files")]
        source: PathBuf,
    },
    Status {
        #[arg(help = "A path to a shard file or a directory containing shard files")]
        source: PathBuf,
    },
    Verify {
        #[arg(help = "A path to a shard file or a directory containing shard files")]
        source: PathBuf,
    },
    Purge {
        #[arg(help = "A path to a shard file or a directory containing shard files")]
        source: PathBuf,
    },
}