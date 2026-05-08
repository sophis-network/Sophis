use sophis_cli_lib::sophis_cli;
use wasm_bindgen::prelude::*;
use workflow_terminal::Options;
use workflow_terminal::Result;

#[wasm_bindgen]
pub async fn load_sophis_wallet_cli() -> Result<()> {
    let options = Options { ..Options::default() };
    sophis_cli(options, None).await?;
    Ok(())
}
