use anyhow::Result;

use super::args::{self, CliConfig};
use super::RunOutcome;

pub type Cli = CliConfig;

pub fn parse() -> Result<Cli> {
    Ok(args::parse())
}

pub fn run(cli: Cli) -> Result<RunOutcome> {
    super::run::execute(cli)
}
