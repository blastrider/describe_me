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
