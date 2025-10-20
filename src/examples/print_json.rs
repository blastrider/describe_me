fn main() -> Result<(), Box<dyn std::error::Error>> {
    let snap = decribe_me::SystemSnapshot::capture()?;
    println!("{}", serde_json::to_string_pretty(&snap)?);
    Ok(())
}
