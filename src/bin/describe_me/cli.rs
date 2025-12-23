use anyhow::Result;

use super::args::{self, CliConfig};

pub type Cli = CliConfig;

pub fn parse() -> Result<Cli> {
    Ok(args::parse())
}

pub fn run(cli: Cli) -> Result<()> {
    super::run::execute(cli)
}
