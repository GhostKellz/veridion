//! `veridion` — a thin CLI over the library.
//!
//! Reads a JSON [`ActionRequest`](veridion::action::ActionRequest) on stdin,
//! authorizes it, and prints the [`Authorization`](veridion::Authorization) as
//! JSON on stdout. Exits non-zero when the action is not permitted, so it can be
//! used as a gate in a shell pipeline:
//!
//! ```text
//! echo '{"action":"exec","resource":"ls -la"}' | veridion && run-the-thing
//! ```
//!
//! The config path is taken from `VERIDION_CONFIG`; without it, the built-in
//! defaults (deny-by-default, in-memory audit) apply.

use std::env;
use std::io::{self, Read};
use std::process::ExitCode;

use veridion::action::ActionRequest;
use veridion::telemetry::Telemetry;
use veridion::{Config, Veridion};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(permitted) => {
            if permitted {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(err) => {
            eprintln!("veridion: {err}");
            ExitCode::from(2)
        }
    }
}

async fn run() -> Result<bool, Box<dyn std::error::Error>> {
    let config = match env::var("VERIDION_CONFIG") {
        Ok(path) => Config::from_file(path)?,
        Err(_) => Config::default(),
    };

    if config.telemetry.enable_tracing {
        Telemetry::new(config.telemetry.clone())?;
    }

    let veridion = Veridion::from_config(&config).await?;

    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let request: ActionRequest = serde_json::from_str(&input)?;

    let auth = veridion.authorize(&request).await?;
    println!("{}", serde_json::to_string_pretty(&auth)?);
    Ok(auth.permitted)
}
