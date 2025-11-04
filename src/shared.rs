use std::ops::Deref;
use std::sync::Arc;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Petit conteneur pour partager des séquences (services, sockets, partitions)
/// sans recopier les données. Clone effectue simplement un `Arc::clone`.
#[derive(Debug, Clone)]
pub struct SharedSlice<T>(Arc<Vec<T>>);

impl<T> SharedSlice<T> {
    pub fn from_vec(vec: Vec<T>) -> Self {
        Self(Arc::new(vec))
    }

    pub fn from_slice(slice: &[T]) -> Self
    where
        T: Clone,
    {
        Self(Arc::new(slice.to_vec()))
    }

    pub fn as_slice(&self) -> &[T] {
        self.0.as_slice()
    }

    pub fn make_mut(&mut self) -> &mut Vec<T>
    where
        T: Clone,
    {
        Arc::make_mut(&mut self.0)
    }

    pub fn into_vec(self) -> Vec<T>
    where
        T: Clone,
    {
        match Arc::try_unwrap(self.0) {
            Ok(vec) => vec,
            Err(arc) => arc.as_ref().to_vec(),
        }
    }
}

impl<T: PartialEq> PartialEq for SharedSlice<T> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: Eq> Eq for SharedSlice<T> {}

impl<T> Deref for SharedSlice<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

#[cfg(feature = "serde")]
impl<T: Serialize> Serialize for SharedSlice<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, T: Deserialize<'de>> Deserialize<'de> for SharedSlice<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = Vec::<T>::deserialize(deserializer)?;
        Ok(Self::from_vec(vec))
    }
}
