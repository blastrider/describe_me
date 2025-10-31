use serde::Serialize;
use std::ops::Deref;
use std::sync::Arc;

/// Petit conteneur pour partager des séquences (services, sockets, partitions)
/// sans recopier les données. Clone effectue simplement un `Arc::clone`.
#[derive(Debug, Clone)]
pub struct SharedSlice<T>(Arc<[T]>);

impl<T> SharedSlice<T> {
    /// Construit une instance à partir d'un vecteur possédé (sans copie supplémentaire).
    pub fn from_vec(vec: Vec<T>) -> Self {
        Self(vec.into())
    }

    /// Construit une instance à partir d'une tranche en copiant les éléments une seule fois.
    pub fn from_slice(slice: &[T]) -> Self
    where
        T: Clone,
    {
        Self(slice.to_vec().into())
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
}

impl<T> Deref for SharedSlice<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Serialize> Serialize for SharedSlice<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}
