//! Helpers communs autour des verrous (`Mutex`/`RwLock`).
//!
//! Politique globale : un lock empoisonné est considéré comme un bug interne grave.
//! Nous paniquons donc avec un message clair plutôt que de tenter de continuer
//! avec un état potentiellement corrompu.

/// Déroule un [`LockResult`](std::sync::LockResult) en panicant si le lock est empoisonné.
/// Utiliser ce helper clarifie l'intention et harmonise les messages de panic.
pub fn lock_expect<T>(lock_result: std::sync::LockResult<T>, who: &'static str) -> T {
    lock_result.unwrap_or_else(|_| panic!("internal bug: poisoned lock in {who}"))
}
