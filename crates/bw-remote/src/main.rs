//! bw-remote CLI
//!
//! A CLI interface for connecting to a user-client through a proxy
//! to request credentials over a secure Noise Protocol channel.

mod command;
mod storage;

use clap::{CommandFactory, FromArgMatches};
use color_eyre::eyre::Result;

use command::{Cli, process_command};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize error handling
    color_eyre::install()?;

    // Parse CLI with color choice based on LLM env var
    let matches = Cli::command().color(command::color_choice()).get_matches();
    let cli = Cli::from_arg_matches(&matches)?;

    // Initialize logging with appropriate level
    let log_level = if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::WARN
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive(log_level.into()),
        )
        .init();

    process_command(cli).await
}
