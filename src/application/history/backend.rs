use crate::domain::DescribeError;
use crate::infrastructure::history::HistorySample;

/// Abstraction de stockage de l'historique (mémoire, disque, etc.).
pub(crate) trait HistoryBackend: Send + Sync {
    fn append(
        &self,
        server_id: &str,
        sample: &HistorySample,
        retention: usize,
    ) -> Result<(), DescribeError>;

    fn read(&self, server_id: &str) -> Result<Vec<HistorySample>, DescribeError>;
}
