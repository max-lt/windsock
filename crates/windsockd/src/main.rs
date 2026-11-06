//! The Windsock daemon: the S3 API on a local port, over an engine and a remote.
//!
//! ```text
//! windsockd init <dir>      write <dir>/windsock.toml for one local proxy
//! windsockd run <config>    serve until SIGINT or SIGTERM, then flush the buffer
//! windsockd cache-trim <config> [bytes]   set the cache limit of the running daemon (0: empty)
//! ```

use std::io::IsTerminal;
use std::path::Path;

use anyhow::{Context, Result, bail};
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
        ["--version"] => {
            println!("{}", windsockd::VERSION);
            Ok(())
        }
        ["init", dir] => windsockd::init(Path::new(dir)),
        ["run", path] => windsockd::run(&Config::load(Path::new(path))?).await,
        ["diagnose", path] => windsockd::diagnose(&Config::load(Path::new(path))?).await,
        ["quarantine", "list", path] => quarantine::list(&Config::load(Path::new(path))?).await,
        ["quarantine", "export", path, out] => {
            quarantine::export(&Config::load(Path::new(path))?, Path::new(out)).await
        }
        ["cache-trim", path] => windsockd::cache_trim(&Config::load(Path::new(path))?, 0).await,
        ["cache-trim", path, bytes] => {
            let bytes = bytes
                .parse()
                .with_context(|| format!("{bytes} is not a number of bytes"))?;
            windsockd::cache_trim(&Config::load(Path::new(path))?, bytes).await
        }
        _ => bail!(
            "usage: windsockd --version | init <dir> | run <config> | diagnose <config> | \
             quarantine list <config> | quarantine export <config> <new dir> | cache-trim \
             <config> [bytes]"
        ),
    }
}
