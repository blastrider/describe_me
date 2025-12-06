pub mod allowlists;
pub mod args;
mod cli;
pub mod exposure;

pub use cli::{parse, run};
pub type Cli = cli::Cli;

pub fn main() -> anyhow::Result<()> {
    let cli: Cli = parse()?;
    run(cli)
}
