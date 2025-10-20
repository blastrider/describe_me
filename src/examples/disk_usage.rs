fn main() -> Result<(), Box<dyn std::error::Error>> {
    let du = describe_me::disk_usage()?;
    println!("Disque total: {} Gio", du.total_bytes as f64 / 1e9);
    for p in du.partitions {
        println!(
            "{}  total={} Gio  dispo={} Gio  fs={:?}",
            p.mount_point,
            p.total_bytes as f64 / 1e9,
            p.available_bytes as f64 / 1e9,
            p.fs_type
        );
    }
    Ok(())
}
