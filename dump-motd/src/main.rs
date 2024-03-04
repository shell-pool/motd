use motd;

fn main() {
    match motd::value() {
        Ok(v) => print!("{}", v),
        Err(e) => eprintln!("Error getting motd: {:?}", e),
    }
}
