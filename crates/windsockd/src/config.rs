//! The configuration file, in TOML.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Engine state, multipart parts and the node key. Relative to the file.
    pub data_dir: PathBuf,
    /// The S3 address, `host:port`.
    #[serde(default = "default_listen")]
    pub listen: String,
    pub remote: RemoteConfig,
    /// The keys that S3 clients sign with. Every key reaches every bucket.
    pub keys: Vec<KeyConfig>,
    #[serde(default = "default_sync_interval")]
    pub sync_interval_secs: u64,
    /// Open S3 connections at most. Default: the soft descriptor limit minus a reserve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<usize>,
    /// Seconds before a connection with no request in progress closes.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    /// Seconds that a body upload can stop before the request is cut.
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
    #[serde(default)]
    pub engine: EngineConfig,
    #[serde(default)]
    pub gc: GcConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum RemoteConfig {
    /// A local directory. Relative to the file.
    Dir { path: PathBuf },
    /// An S3 bucket, over HTTP, or HTTPS with the feature `tls`.
    S3 {
        endpoint: String,
        bucket: String,
        #[serde(default)]
        prefix: String,
        #[serde(default = "default_region")]
        region: String,
        access_key: String,
        secret_key: String,
        /// PEM file of a private CA to trust, for https. Relative to the file.
        #[serde(default)]
        ca_file: Option<PathBuf>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    pub access_key: String,
    pub secret_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EngineConfig {
    /// Zero turns the chunk cache off.
    pub cache_bytes: u64,
    pub flush_delay_ms: u64,
    pub buffer_limit_bytes: u64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        let engine = engine::Config::default();
        Self {
            cache_bytes: engine.cache_bytes,
            flush_delay_ms: engine.flush_delay.as_millis() as u64,
            buffer_limit_bytes: engine.buffer_limit,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GcConfig {
    /// This proxy runs the GC. Turn it on for one proxy per remote.
    pub enabled: bool,
    pub interval_secs: u64,
    /// H of the GC rules. Every proxy of a remote must use the same value: writers use it too.
    pub horizon_secs: u64,
    pub retention_secs: u64,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 3600,
            horizon_secs: 24 * 3600,
            retention_secs: 24 * 3600,
        }
    }
}

fn default_listen() -> String {
    "127.0.0.1:9000".to_string()
}

fn default_idle_timeout() -> u64 {
    60
}

fn default_request_timeout() -> u64 {
    300
}

fn default_sync_interval() -> u64 {
    10
}

fn default_region() -> String {
    "us-east-1".to_string()
}

impl Config {
    /// Reads a file. Relative paths in it become relative to the file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let mut config: Self =
            toml::from_str(&text).with_context(|| format!("{} is not valid", path.display()))?;

        if config.keys.is_empty() {
            bail!(
                "{}: at least one [[keys]] entry is required",
                path.display()
            );
        }

        let base = path.parent().unwrap_or(Path::new("."));
        config.data_dir = base.join(&config.data_dir);
        match &mut config.remote {
            RemoteConfig::Dir { path } => *path = base.join(&*path),
            RemoteConfig::S3 {
                ca_file: Some(path),
                ..
            } => *path = base.join(&*path),
            RemoteConfig::S3 { .. } => {}
        }

        Ok(config)
    }

    pub fn keys(&self) -> HashMap<String, String> {
        self.keys
            .iter()
            .map(|k| (k.access_key.clone(), k.secret_key.clone()))
            .collect()
    }

    pub fn engine(&self) -> engine::Config {
        engine::Config {
            cache_bytes: self.engine.cache_bytes,
            flush_delay: Duration::from_millis(self.engine.flush_delay_ms),
            buffer_limit: self.engine.buffer_limit_bytes,
            gc_horizon: Duration::from_secs(self.gc.horizon_secs),
            retention: Duration::from_secs(self.gc.retention_secs),
            ..engine::Config::default()
        }
    }

    /// A configuration for one local proxy: a remote directory next to the data, and a fresh key pair.
    pub fn local() -> Result<Self> {
        Ok(Self {
            data_dir: PathBuf::from("data"),
            listen: default_listen(),
            remote: RemoteConfig::Dir {
                path: PathBuf::from("remote"),
            },
            keys: vec![KeyConfig {
                access_key: format!(
                    "WS{}",
                    random_chars(18, b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")?
                ),
                secret_key: hex::encode(random_bytes::<20>()?),
            }],
            sync_interval_secs: default_sync_interval(),
            max_connections: None,
            idle_timeout_secs: default_idle_timeout(),
            request_timeout_secs: default_request_timeout(),
            engine: EngineConfig::default(),
            gc: GcConfig::default(),
        })
    }
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .context("cannot read /dev/urandom")?;
    Ok(bytes)
}

fn random_chars(len: usize, alphabet: &[u8]) -> Result<String> {
    let bytes = random_bytes::<64>()?;
    Ok(bytes[..len]
        .iter()
        .map(|b| alphabet[usize::from(*b) % alphabet.len()] as char)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_config_roundtrips_through_toml() {
        let config = Config::local().unwrap();
        let text = toml::to_string(&config).unwrap();

        assert_eq!(toml::from_str::<Config>(&text).unwrap(), config);
        assert!(text.contains("type = \"dir\""));
        assert_eq!(config.keys[0].secret_key.len(), 40);
        assert_ne!(Config::local().unwrap().keys, config.keys);
    }

    #[test]
    fn test_paths_are_relative_to_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("windsock.toml");
        std::fs::write(&path, toml::to_string(&Config::local().unwrap()).unwrap()).unwrap();

        let config = Config::load(&path).unwrap();

        assert_eq!(config.data_dir, dir.path().join("data"));
        assert_eq!(
            config.remote,
            RemoteConfig::Dir {
                path: dir.path().join("remote")
            }
        );
    }

    #[test]
    fn test_ca_file_is_relative_to_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("windsock.toml");
        let text = "data_dir = \"d\"\n[[keys]]\naccess_key = \"c\"\nsecret_key = \"d\"\n\
                    [remote]\ntype = \"s3\"\nendpoint = \"https://s3.example.com\"\n\
                    bucket = \"b\"\naccess_key = \"a\"\nsecret_key = \"s\"\nca_file = \"ca.pem\"\n";
        std::fs::write(&path, text).unwrap();

        let config = Config::load(&path).unwrap();

        assert!(matches!(
            config.remote,
            RemoteConfig::S3 { ca_file: Some(ref ca), .. } if *ca == dir.path().join("ca.pem")
        ));
    }

    #[test]
    fn test_s3_remote_and_defaults() {
        let text = r#"
            data_dir = "/var/lib/windsock"
            [remote]
            type = "s3"
            endpoint = "http://10.0.0.2:9000"
            bucket = "store"
            access_key = "a"
            secret_key = "b"
            [[keys]]
            access_key = "c"
            secret_key = "d"
            [gc]
            enabled = true
        "#;

        let config: Config = toml::from_str(text).unwrap();

        assert!(
            matches!(config.remote, RemoteConfig::S3 { ref region, .. } if region == "us-east-1")
        );
        assert!(config.gc.enabled);
        assert_eq!(config.gc.horizon_secs, 86_400);
        assert_eq!(config.listen, "127.0.0.1:9000");
        assert_eq!(config.engine().gc_horizon, Duration::from_secs(24 * 3600));
    }

    #[test]
    fn test_unknown_field_and_missing_keys_are_rejected() {
        assert!(toml::from_str::<Config>("data_dir = \"d\"\nlisten_on = \"x\"").is_err());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("windsock.toml");
        std::fs::write(
            &path,
            "data_dir = \"d\"\nkeys = []\n[remote]\ntype = \"dir\"\npath = \"r\"\n",
        )
        .unwrap();
        assert!(Config::load(&path).is_err());
    }
}
