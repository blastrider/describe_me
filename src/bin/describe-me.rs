#![forbid(unsafe_code)]

extern crate describe_me as describe_me_lib;

mod describe_me;

fn main() -> anyhow::Result<()> {
    describe_me::main()
}
