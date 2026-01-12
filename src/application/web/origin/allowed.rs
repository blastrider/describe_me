use axum::http::Uri;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct AllowedOrigin {
    scheme: OriginScheme,
    host: String,
    port: Option<u16>,
}

impl AllowedOrigin {
    pub(super) fn parse(input: &str) -> Result<Self, String> {
        let uri: Uri = input.parse::<Uri>().map_err(|err| err.to_string())?;
        let scheme = match uri.scheme_str() {
            Some(value) => OriginScheme::parse(value)
                .ok_or_else(|| format!("schéma non supporté: {value} (attendu http ou https)"))?,
            None => {
                return Err("origin incomplet: schéma requis (http ou https)".into());
            }
        };
        let host = uri
            .host()
            .ok_or_else(|| "origin incomplet: hôte requis".to_string())?
            .to_owned();
        let port = uri.port_u16();
        if uri.path() != "/" && !uri.path().is_empty() {
            return Err("origin ne doit pas contenir de chemin".into());
        }
        if uri.query().is_some() {
            return Err("origin ne doit pas contenir de query string".into());
        }
        Ok(Self { scheme, host, port })
    }

    pub(super) fn as_origin(&self) -> String {
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match self.port {
            Some(port) => format!("{}://{}:{}", self.scheme.as_str(), host, port),
            None => format!("{}://{}", self.scheme.as_str(), host),
        }
    }

    pub(super) fn matches(&self, candidate: &Uri) -> bool {
        let Some(host) = candidate.host() else {
            return false;
        };
        if !host.eq_ignore_ascii_case(&self.host) {
            return false;
        }
        match candidate.scheme_str() {
            Some(value) if self.scheme.matches(value) => {}
            _ => return false,
        }
        let candidate_port = candidate
            .port_u16()
            .or_else(|| default_port(candidate.scheme_str()));
        match self.port {
            Some(port) => candidate_port == Some(port),
            None => candidate_port == default_port(Some(self.scheme.as_str())),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub(super) enum OriginScheme {
    #[default]
    Http,
    Https,
}

impl OriginScheme {
    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            "http" | "HTTP" => Some(OriginScheme::Http),
            "https" | "HTTPS" => Some(OriginScheme::Https),
            _ => None,
        }
    }

    pub(super) fn matches(&self, other: &str) -> bool {
        match self {
            OriginScheme::Http => other.eq_ignore_ascii_case("http"),
            OriginScheme::Https => other.eq_ignore_ascii_case("https"),
        }
    }

    pub(super) fn as_str(&self) -> &'static str {
        match self {
            OriginScheme::Http => "http",
            OriginScheme::Https => "https",
        }
    }
}

pub(super) fn default_port(scheme: Option<&str>) -> Option<u16> {
    match scheme {
        Some("https") => Some(443),
        Some("http") => Some(80),
        _ => None,
    }
}
