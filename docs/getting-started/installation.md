# Installation

Veridion is a Rust library crate with an optional thin CLI binary. There are three ways
to use it.

Requires Rust 1.96+ (edition 2024).

## From Source

```bash
git clone https://github.com/ghostkellz/veridion.git
cd veridion

cargo build --release        # library + CLI binary at target/release/veridion
cargo test                   # run the test suite
cargo install --path .       # install the CLI to ~/.cargo/bin
```

## As a Cargo Dependency

Add Veridion to another Rust project to authorize agent actions in-process:

```toml
[dependencies]
veridion = { path = "." }   # or a version once published
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

```rust
use veridion::{Config, Veridion};
use veridion::action::{ActionRequest, Subject, actions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let veridion = Veridion::from_config(&Config::default()).await?;
    let request = ActionRequest::new(actions::EXEC, "rm -rf /tmp/cache")
        .subject(Subject::new("jarvis").with_role("agent"))
        .attr("repo", "veridion");
    let auth = veridion.authorize(&request).await?;
    if auth.permitted {
        // run the command
    }
    Ok(())
}
```

See the [Library API](../reference/library-api.md) for the full surface.

## Using the CLI Binary

The binary is a thin stdin-to-stdout CLI, not a daemon: it reads a JSON `ActionRequest`
on stdin and prints an `Authorization` JSON document on stdout. It exits `0` when the
action is permitted, `1` when it is not, and `2` on error.

```bash
echo '{"action":"exec","resource":"ls -la","subject":{"id":"jarvis","roles":["agent"]}}' | veridion
```

## Verifying the Build

```bash
cargo build
cargo test                          # 16 unit + 5 integration + 2 doctests
cargo run --example jarvis_integration
```

Veridion reads its config path from `VERIDION_CONFIG`. If the variable is unset, the
built-in defaults apply (deny-by-default, sqlite audit, risk analysis on).

## Next Steps

- [Configuration](configuration.md) - All settings and defaults
- [Quickstart](quickstart.md) - Authorize your first action
