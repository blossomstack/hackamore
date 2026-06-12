//! `hackamore-agent` — the consumer-side setup CLI (thin wrapper over the `hackamore_agent`
//! library crate).
//!
//! A sandboxed consumer runs one command to configure its stock tools (`gh`/`kubectl`/
//! `aws`/SDKs) to reach upstreams through hackamore. It fetches a provision doc from the
//! reserved `/.hackamore/provision` path on the proxy listener (`--hackamore-url`) — the only
//! address a sandbox can reach — and renders native config from it.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "hackamore-agent",
    about = "Configure stock tools to reach hackamore"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch and pretty-print the raw provision doc.
    Show(Common),
    /// Print shell `export` lines (for `eval "$(hackamore-agent env ...)"`).
    Env(Common),
    /// Print a human-readable summary of what the token can reach.
    Status(Common),
    /// Write native tool config (kubeconfig / ~/.aws / git) into a home directory.
    Setup(SetupArgs),
    /// Remove the native tool config hackamore previously wrote (per its manifest).
    Teardown(TeardownArgs),
}

#[derive(clap::Args)]
struct Common {
    /// Base URL of the hackamore proxy listener, e.g. http://127.0.0.1:9090 (provision is
    /// fetched from the reserved /.hackamore/provision path).
    #[arg(long)]
    hackamore_url: String,
    /// The hackamore token to provision for.
    #[arg(long)]
    token: String,
}

#[derive(clap::Args)]
struct SetupArgs {
    #[command(flatten)]
    common: Common,
    /// Home directory to write native config into (defaults to $HOME).
    #[arg(long)]
    home: Option<std::path::PathBuf>,
}

#[derive(clap::Args)]
struct TeardownArgs {
    /// Home directory to remove hackamore-written config from (defaults to $HOME).
    #[arg(long)]
    home: Option<std::path::PathBuf>,
}

/// Resolve a `--home` override or fall back to `$HOME`.
fn resolve_home(
    explicit: Option<std::path::PathBuf>,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    explicit
        .or_else(|| std::env::var_os("HOME").map(Into::into))
        .ok_or_else(|| "no --home and $HOME is unset".into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Show(c) => {
            let doc = hackamore_agent::fetch_provision(&c.hackamore_url, &c.token).await?;
            println!("{}", serde_json::to_string_pretty(&doc)?);
        }
        Command::Env(c) => {
            let doc = hackamore_agent::fetch_provision(&c.hackamore_url, &c.token).await?;
            print!("{}", hackamore_agent::render_env(&doc));
        }
        Command::Status(c) => {
            let doc = hackamore_agent::fetch_provision(&c.hackamore_url, &c.token).await?;
            print!("{}", hackamore_agent::render_status(&doc));
        }
        Command::Setup(args) => {
            let doc =
                hackamore_agent::fetch_provision(&args.common.hackamore_url, &args.common.token)
                    .await?;
            let home = resolve_home(args.home)?;
            let written = hackamore_agent::write_configs(&home, &doc)?;
            for p in &written {
                println!("wrote {}", p.display());
            }
        }
        Command::Teardown(args) => {
            let home = resolve_home(args.home)?;
            let removed = hackamore_agent::teardown(&home)?;
            for p in &removed {
                println!("removed {}", p.display());
            }
        }
    }
    Ok(())
}
