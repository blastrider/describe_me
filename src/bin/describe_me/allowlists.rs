#[cfg(feature = "web")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CliListOrigin {
    None,
    RuntimeDefault,
    ExplicitCli,
}

#[cfg(feature = "web")]
impl CliListOrigin {
    pub fn from_values(values: &[String]) -> Self {
        if values.is_empty() {
            Self::None
        } else {
            Self::ExplicitCli
        }
    }

    pub fn runtime_slice<'a>(&self, values: &'a [String]) -> Option<&'a [String]> {
        match self {
            Self::RuntimeDefault => Some(values),
            _ => None,
        }
    }

    pub fn cli_slice<'a>(&self, values: &'a [String]) -> Option<&'a [String]> {
        match self {
            Self::ExplicitCli => Some(values),
            _ => None,
        }
    }
}

#[cfg(feature = "web")]
pub fn resolve_web_list(
    cli_values: Option<&[String]>,
    config_values: Option<&[String]>,
    runtime_values: Option<&[String]>,
) -> Vec<String> {
    if let Some(values) = cli_values {
        if !values.is_empty() {
            return values.to_vec();
        }
    }
    if let Some(values) = config_values {
        if !values.is_empty() {
            return values.to_vec();
        }
    }
    if let Some(values) = runtime_values {
        if !values.is_empty() {
            return values.to_vec();
        }
    }
    Vec::new()
}

#[cfg(all(test, feature = "web"))]
mod tests {
    use super::*;

    #[test]
    fn resolve_web_list_respects_precedence() {
        struct Case<'a> {
            name: &'a str,
            cli: Option<&'a [String]>,
            config: Option<&'a [String]>,
            runtime: Option<&'a [String]>,
            expected: Vec<String>,
        }

        let cli_values = vec!["1.1.1.1".to_string()];
        let config_values = vec!["2.2.2.2".to_string()];
        let runtime_values = vec!["3.3.3.3".to_string()];

        let cases = [
            Case {
                name: "cli_overrides_config_and_runtime",
                cli: Some(&cli_values),
                config: Some(&config_values),
                runtime: Some(&runtime_values),
                expected: cli_values.clone(),
            },
            Case {
                name: "config_used_when_cli_missing",
                cli: None,
                config: Some(&config_values),
                runtime: Some(&runtime_values),
                expected: config_values.clone(),
            },
            Case {
                name: "runtime_used_when_cli_and_config_missing",
                cli: None,
                config: None,
                runtime: Some(&runtime_values),
                expected: runtime_values.clone(),
            },
        ];

        for case in cases {
            let resolved = resolve_web_list(case.cli, case.config, case.runtime);
            assert_eq!(resolved, case.expected, "case={}", case.name);
        }
    }
}
