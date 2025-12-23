pub mod allowlists;
pub mod args;
mod cli;
mod cmd_history;
mod cmd_logs;
mod cmd_metadata;
mod cmd_plugin;
pub mod exposure;
mod run;

pub use cli::{parse, run};
pub type Cli = cli::Cli;
pub use run::RunOutcome;

pub fn main() -> anyhow::Result<RunOutcome> {
    let cli: Cli = parse()?;
    run(cli)
}
