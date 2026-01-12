#[cfg(test)]
use super::policy::OriginPolicy;
#[cfg(test)]
use axum::extract::Request;

#[cfg(test)]
pub(crate) fn is_origin_allowed<B>(req: &Request<B>, policy: &OriginPolicy) -> bool {
    policy.allows(req)
}
