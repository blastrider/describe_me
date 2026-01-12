mod allowed;
mod check;
mod layer;
mod policy;

#[cfg(test)]
mod tests;

pub(crate) use layer::OriginCheckLayer;
pub(crate) use policy::OriginPolicy;

#[cfg(test)]
pub(crate) use check::is_origin_allowed;
