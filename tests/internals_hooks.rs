#![cfg(feature = "internals")]

use describe_me::internals::metadata::{init_metadata_store_for_internals, MetadataStore};

#[test]
fn internals_metadata_hooks_compile() {
    let _ = init_metadata_store_for_internals as fn(MetadataStore);
}
