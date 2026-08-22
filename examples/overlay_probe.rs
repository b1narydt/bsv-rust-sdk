//! Live probe: reproduce the enterprise box's ls_ship discovery failure.
//! Run: cargo run --example overlay_probe

use bsv::services::overlay_tools::types::LookupQuestion;
use bsv::services::overlay_tools::{LookupResolver, LookupResolverConfig, Network};

#[tokio::main]
async fn main() {
    let resolver = LookupResolver::new(LookupResolverConfig {
        network: Network::Mainnet,
        ..Default::default()
    });
    let question = LookupQuestion {
        service: "ls_ship".to_string(),
        query: serde_json::json!({ "topics": ["tm_messagebox", "tm_did"] }),
    };
    match resolver.query(&question, Some(10_000)).await {
        Ok(answer) => println!("OK: {answer:?}"),
        Err(e) => println!("ERR: {e}"),
    }
}
