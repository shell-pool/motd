fn main() {
    motd::handle_reexec();

    if let Err(e) = run() {
        eprintln!("Error getting motd: {}", e);
    }
}

fn run() -> Result<(), motd::Error> {
    let motd_resolver = motd::Resolver::new(motd::PamMotdResolutionStrategy::Auto)?;
    print!(
        "{}",
        motd_resolver.value(motd::ArgResolutionStrategy::Auto)?
    );
    Ok(())
}
