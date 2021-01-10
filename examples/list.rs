fn main() -> std::io::Result<()> {
    let list = corsairmi::list()?;
    if list.is_empty() {
        println!("No power supplies found");
    } else {
        println!("Found power supplies:");
        for (idx, path) in corsairmi::list()?.iter().enumerate() {
            println!("{}: {}", idx, path.to_string_lossy());
        }
    }
    Ok(())
}
