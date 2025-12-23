#![forbid(unsafe_code)]

extern crate describe_me as describe_me_lib;

mod describe_me;

fn main() -> anyhow::Result<()> {
    match describe_me::main()? {
        describe_me::RunOutcome::Completed => Ok(()),
        describe_me::RunOutcome::Exit { code, messages } => {
            for message in messages {
                eprintln!("{message}");
            }
            std::process::exit(code);
        }
    }
}
