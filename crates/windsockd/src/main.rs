//! The Windsock daemon: the S3 API on a local port, over an engine and a remote.
//!
//! ```text
//! windsockd init <dir>      write <dir>/windsock.toml for one local proxy
//! windsockd run <config>    serve until SIGINT or SIGTERM, then flush the buffer
//! ```

use std::io::IsTerminal;
use std::path::Path;

use anyhow::{Result, bail};
use tracing_subscriber::EnvFilter;
use windsockd::{Config, quarantine};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,fjall=warn,lsm_tree=warn")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["init", dir] => windsockd::init(Path::new(dir)),
        ["run", path] => windsockd::run(&Config::load(Path::new(path))?).await,
        ["diagnose", path] => windsockd::diagnose(&Config::load(Path::new(path))?).await,
        ["quarantine", "list", path] => quarantine::list(&Config::load(Path::new(path))?).await,
        ["quarantine", "export", path, out] => {
            quarantine::export(&Config::load(Path::new(path))?, Path::new(out)).await
        }
        _ => bail!(
            "usage: windsockd init <dir> | run <config> | diagnose <config> | quarantine list \
             <config> | quarantine export <config> <new dir>"
        ),
    }
}
