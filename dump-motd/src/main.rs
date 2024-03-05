fn main() {
    motd::handle_reexec();

    match motd::value(
        motd::PamMotdResolutionStrategy::Auto,
        motd::ArgResolutionStrategy::Auto,
    ) {
        Ok(v) => print!("{}", v),
        Err(e) => eprintln!("Error getting motd: {}", e),
    }
}
