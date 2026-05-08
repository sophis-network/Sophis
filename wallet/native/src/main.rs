use sophis_cli_lib::{TerminalOptions, sophis_cli};

#[tokio::main]
async fn main() {
    let result = sophis_cli(TerminalOptions::new().with_prompt("$ "), None).await;
    if let Err(err) = result {
        println!("{err}");
    }
}
