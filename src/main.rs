use anyhow::Result;
use clap::Parser;
use qshard::cli::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Create { output_dir, id } => {
            qshard::run_create_command(&output_dir, id)?;
        }
        Commands::Recover { source } => {
            qshard::run_recover_command(&source)?;
        }
        Commands::Status { source } => {
            qshard::run_status_command(&source)?;
        }
        Commands::Verify { source } => {
            qshard::run_verify_command(&source)?;
        }
        Commands::Purge { source } => {
            qshard::run_purge_command(&source)?;
        }
    }

    Ok(())
}