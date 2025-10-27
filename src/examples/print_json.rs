fn main() -> Result<(), Box<dyn std::error::Error>> {
    let snap = describe_me::SystemSnapshot::capture()?;
    let view = describe_me::SnapshotView::new(&snap, describe_me::Exposure::default());
    println!("{}", serde_json::to_string_pretty(&view)?);
    Ok(())
}
