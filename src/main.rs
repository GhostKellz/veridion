use std::env;

use tracing::info;
use veridion::{Config, Firewall};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = env::var("VERIDION_CONFIG").unwrap_or_else(|_| "veridion.toml".to_string());

    let config = match Config::from_file(&config_path) {
        Ok(config) => config,
        Err(err) => {
            eprintln!(
                "failed to load config from '{}': {} -- falling back to default development config",
                config_path, err
            );
            Config::default_insecure()
        }
    };

    let firewall = Firewall::new(config).await?;
    info!("starting veridion firewall");
    firewall.serve().await?;
    Ok(())
}
