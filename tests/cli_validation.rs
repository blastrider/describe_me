use clap::{error::ErrorKind, Parser};
#[path = "../src/cli/opts.rs"]
mod cli_opts;
use cli_opts::Opts;

#[test]
fn pretty_requires_json() {
    let err = Opts::try_parse_from(["describe-me", "--pretty"]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
}

#[test]
fn web_interval_bounds() {
    // borne basse OK
    let _ = Opts::parse_from(["describe-me", "--json", "--pretty", "--web-interval", "1"]);

    // hors bornes -> erreur
    let err = Opts::try_parse_from(["describe-me", "--web-interval", "0"]).unwrap_err();
    assert!(err.to_string().contains("valid"));

    let err = Opts::try_parse_from(["describe-me", "--web-interval", "999999"]).unwrap_err();
    assert!(err.to_string().contains("valid"));
}
