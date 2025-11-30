use std::sync::Arc;

#[cfg(feature = "serde")]
use crate::application::containers::ContainersCacheService;
use crate::application::history::{HistoryMode, HistoryService, HistorySettings};
use crate::domain::DescribeError;
use crate::domain::HistoryProfile;
use crate::infrastructure::storage::{acquire_backend_arc, MetadataBackend, MetadataStore};
use std::sync::Mutex;

/// Contexte applicatif injectable (métadonnées, historique, cache conteneurs).
#[allow(dead_code)]
#[derive(Clone)]
pub struct AppContext {
    metadata_backend: Arc<dyn MetadataBackend>,
    history: HistoryService,
    #[cfg(feature = "serde")]
    containers: Arc<ContainersCacheService>,
}

impl AppContext {
    pub fn new_default() -> Result<Self, DescribeError> {
        let metadata_backend = acquire_backend_arc()?;
        Ok(Self {
            metadata_backend,
            history: HistoryService::new(),
            #[cfg(feature = "serde")]
            containers: Arc::new(ContainersCacheService::default()),
        })
    }

    pub fn in_memory() -> Self {
        let metadata_backend = Arc::new(InMemoryMetadataBackend::default());
        let history = HistoryService::new();
        let mut settings = HistorySettings::for_profile(HistoryProfile::Default);
        settings.mode = HistoryMode::InMemory;
        // Ignorer l'erreur éventuelle: le backend in-memory est toujours disponible.
        let _ = history.configure(settings);
        Self {
            metadata_backend,
            history,
            #[cfg(feature = "serde")]
            containers: Arc::new(ContainersCacheService::default()),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn with_metadata_backend(metadata_backend: Arc<dyn MetadataBackend>) -> Self {
        Self {
            metadata_backend,
            history: HistoryService::new(),
            #[cfg(feature = "serde")]
            containers: Arc::new(ContainersCacheService::default()),
        }
    }

    pub(crate) fn metadata_store(&self) -> MetadataStore {
        MetadataStore::new_with_backend(Arc::clone(&self.metadata_backend))
    }

    pub fn history(&self) -> &HistoryService {
        &self.history
    }

    #[cfg(feature = "serde")]
    pub fn containers_cache(&self) -> &ContainersCacheService {
        &self.containers
    }
}

#[allow(dead_code)]
#[derive(Default)]
struct InMemoryMetaState {
    description: Option<String>,
    tags: Option<String>,
}

#[derive(Clone, Default)]
struct InMemoryMetadataBackend {
    state: Arc<Mutex<InMemoryMetaState>>,
}

impl MetadataBackend for InMemoryMetadataBackend {
    fn set_description(&self, text: &str) -> Result<(), DescribeError> {
        let mut guard = self.state.lock().expect("in-memory meta mutex");
        guard.description = if text.trim().is_empty() {
            None
        } else {
            Some(text.to_owned())
        };
        Ok(())
    }

    fn get_description(&self) -> Result<Option<String>, DescribeError> {
        let guard = self.state.lock().expect("in-memory meta mutex");
        Ok(guard.description.clone())
    }

    fn clear_description(&self) -> Result<(), DescribeError> {
        let mut guard = self.state.lock().expect("in-memory meta mutex");
        guard.description = None;
        Ok(())
    }

    fn set_tags_raw(&self, payload: &str) -> Result<(), DescribeError> {
        let mut guard = self.state.lock().expect("in-memory meta mutex");
        guard.tags = if payload.is_empty() {
            None
        } else {
            Some(payload.to_owned())
        };
        Ok(())
    }

    fn get_tags_raw(&self) -> Result<Option<String>, DescribeError> {
        let guard = self.state.lock().expect("in-memory meta mutex");
        Ok(guard.tags.clone())
    }

    fn clear_tags(&self) -> Result<(), DescribeError> {
        let mut guard = self.state.lock().expect("in-memory meta mutex");
        guard.tags = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::metadata::{
        add_server_tags_with, clear_server_description_with, clear_server_tags_with,
        load_server_description_with, load_server_tags_with, set_server_description_with,
        set_server_tags_with,
    };
    #[cfg(feature = "systemd")]
    use crate::domain::ServiceInfo;
    use crate::domain::{DiskUsage, SystemSnapshot};
    use crate::ContainersSnapshot;
    use crate::SharedSlice;
    use std::time::Duration;

    #[test]
    fn in_memory_context_roundtrips_metadata() {
        let ctx = AppContext::in_memory();
        set_server_description_with(&ctx, "hello").expect("set");
        set_server_tags_with(&ctx, ["foo", "bar"]).expect("set tags");
        let desc = load_server_description_with(&ctx).expect("get");
        assert_eq!(desc.as_deref(), Some("hello"));
        let tags = load_server_tags_with(&ctx).expect("tags");
        assert_eq!(tags, vec!["bar", "foo"]);
        add_server_tags_with(&ctx, ["baz"]).expect("add tags");
        clear_server_description_with(&ctx).expect("clear desc");
        clear_server_tags_with(&ctx).expect("clear tags");
    }

    #[test]
    fn in_memory_history_can_configure_and_query() {
        let ctx = AppContext::in_memory();
        let settings = ctx.history().settings_snapshot();
        assert!(settings.enabled);
        assert!(matches!(settings.mode, HistoryMode::InMemory));
        let snapshot = dummy_snapshot();
        ctx.history().record_snapshot(&snapshot);
        let server_id = ctx.history().default_server_id().expect("server id");
        let series = ctx
            .history()
            .query_series(&server_id, Duration::from_secs(60), 10, 1)
            .expect("query series");
        assert!(!series.points.is_empty());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn containers_cache_can_be_injected_for_tests() {
        let service = ContainersCacheService::default();
        let snapshot = ContainersSnapshot {
            summary: None,
            containers: None,
        };
        service.inject(snapshot.clone());
        let cached = service.capture().expect("capture from injected cache");
        assert!(cached.containers.is_none());
    }

    #[test]
    fn multiple_contexts_are_isolated() {
        let ctx1 = AppContext::in_memory();
        let ctx2 = AppContext::in_memory();

        set_server_description_with(&ctx1, "ctx1-desc").expect("desc1");
        set_server_tags_with(&ctx1, ["a", "b"]).expect("tags1");

        set_server_description_with(&ctx2, "ctx2-desc").expect("desc2");
        set_server_tags_with(&ctx2, ["x", "y"]).expect("tags2");

        let mut hist1 = HistorySettings::for_profile(HistoryProfile::Default);
        hist1.mode = HistoryMode::InMemory;
        ctx1.history().configure(hist1).expect("hist cfg1");
        let mut hist2 = HistorySettings::for_profile(HistoryProfile::Default);
        hist2.mode = HistoryMode::InMemory;
        let _ = ctx2.history().configure(hist2);
        ctx1.history().record_snapshot(&dummy_snapshot());

        let desc1 = load_server_description_with(&ctx1).expect("load1");
        let desc2 = load_server_description_with(&ctx2).expect("load2");
        assert_eq!(desc1.as_deref(), Some("ctx1-desc"));
        assert_eq!(desc2.as_deref(), Some("ctx2-desc"));

        let tags1 = load_server_tags_with(&ctx1).expect("tags1");
        let tags2 = load_server_tags_with(&ctx2).expect("tags2");
        assert_eq!(tags1, vec!["a", "b"]);
        assert_eq!(tags2, vec!["x", "y"]);

        let id1 = ctx1.history().default_server_id().expect("id1");
        let series1 = ctx1
            .history()
            .query_series(&id1, Duration::from_secs(60), 10, 1)
            .expect("series1");
        assert!(!series1.points.is_empty());

        let id2 = ctx2.history().default_server_id().expect("id2");
        let series2 = ctx2
            .history()
            .query_series(&id2, Duration::from_secs(60), 10, 1)
            .ok();
        // ctx2 n'a pas de snapshot enregistré, donc aucun point
        assert!(series2.is_none() || series2.unwrap().points.is_empty());
    }

    fn dummy_snapshot() -> SystemSnapshot {
        SystemSnapshot {
            hostname: "host".into(),
            os: None,
            kernel: None,
            uptime_seconds: 0,
            cpu_count: 1,
            load_average: (0.0, 0.0, 0.0),
            total_memory_bytes: 1024,
            used_memory_bytes: 512,
            total_swap_bytes: 0,
            used_swap_bytes: 0,
            disk_usage: Some(DiskUsage {
                total_bytes: 1024,
                available_bytes: 512,
                used_bytes: 512,
                partitions: SharedSlice::from_vec(Vec::new()),
            }),
            #[cfg(feature = "systemd")]
            services_running: SharedSlice::from_vec(Vec::<ServiceInfo>::new()),
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "net")]
            network_traffic: None,
            containers: None,
            updates: None,
            extensions: None,
        }
    }
}
