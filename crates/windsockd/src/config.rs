//! The configuration file, in TOML.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// A secret string from the configuration. Its `Debug` form hides it, so no log shows it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Engine state, multipart parts and the node key. Relative to the file.
    pub data_dir: PathBuf,
    /// The secret of the remote, shared by all its proxies. Relative to the file.
    #[serde(default = "default_repo_key")]
    pub repo_key: PathBuf,
    /// The S3 address, `host:port`.
    #[serde(default = "default_listen")]
    pub listen: String,
    pub remote: RemoteConfig,
    /// Keys with [`s3api::Grants::full`]. Empty when a [`s3api::KeyStore`] gives the keys.
    #[serde(default)]
    pub keys: Vec<KeyConfig>,
    #[serde(default = "default_sync_interval")]
    pub sync_interval_secs: u64,
    /// Open S3 connections at most. Default: (soft descriptor limit - 256) / 2, at most 4096, as a
    /// connection can hold a socket and a file. A value that needs more descriptors refuses the start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<usize>,
    /// Seconds before a connection with no request in progress closes.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    /// Seconds that a body upload can stop before the request is cut.
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
    /// A multipart upload with no initiate and no part for this time is removed, with its parts.
    #[serde(default = "default_uploads_expire")]
    pub uploads_expire_secs: u64,
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
        secret_key: Secret,
        /// PEM file of a private CA to trust, for https. Relative to the file.
        #[serde(default)]
        ca_file: Option<PathBuf>,
    },
}

/// Where the S3 keys come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySource {
    /// The [[keys]] entries of the configuration.
    Config,
    /// A [`s3api::KeyStore`] that the caller gives.
    Store,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    pub access_key: String,
    pub secret_key: Secret,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EngineConfig {
    /// Zero turns the chunk cache off.
    pub cache_bytes: u64,
    pub flush_delay_ms: u64,
    pub buffer_limit_bytes: u64,
    /// The parts of all open multipart uploads together.
    pub parts_limit_bytes: u64,
    /// The bytes of GET pieces in flight on all connections together.
    pub read_budget_bytes: u64,
    /// Pieces that a GET of the remote reads ahead at most. 0 turns read-ahead off.
    pub read_ahead: usize,
    /// A copy of an object of at least this size writes a new manifest of the stored chunks and
    /// moves no data. 0, the default, turns it off.
    pub copy_ref_min: u64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        let engine = engine::Config::default();
        Self {
            cache_bytes: engine.cache_bytes,
            flush_delay_ms: engine.flush_delay.as_millis() as u64,
            buffer_limit_bytes: engine.buffer_limit,
            parts_limit_bytes: s3api::DEFAULT_PARTS_LIMIT,
            read_budget_bytes: engine.read_budget,
            read_ahead: engine.read_ahead,
            copy_ref_min: engine.copy_ref_min,
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
    /// The clock skew that the late write rule allows. Must be under `retention_secs`.
    pub late_margin_secs: u64,
    /// The GC writes a snapshot when the latest one is this old.
    pub snapshot_interval_secs: u64,
    /// The GC retires each chain with no entry for max(R, H) + M, so writers leave it out of their
    /// seen. Off by default.
    pub retire_chains: bool,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 3600,
            horizon_secs: 24 * 3600,
            retention_secs: 24 * 3600,
            late_margin_secs: 3600,
            snapshot_interval_secs: 24 * 3600,
            retire_chains: false,
        }
    }
}

fn default_listen() -> String {
    "127.0.0.1:9000".to_string()
}

fn default_repo_key() -> PathBuf {
    PathBuf::from("repo.key")
}

fn default_idle_timeout() -> u64 {
    60
}

fn default_request_timeout() -> u64 {
    300
}

const MIN_UPLOADS_EXPIRE_SECS: u64 = 3600;

fn default_uploads_expire() -> u64 {
    7 * 24 * 3600
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

        // A short expiry removes uploads that clients still write.
        if config.uploads_expire_secs < MIN_UPLOADS_EXPIRE_SECS {
            bail!(
                "{}: uploads_expire_secs is {}, under the minimum of {MIN_UPLOADS_EXPIRE_SECS}",
                path.display(),
                config.uploads_expire_secs
            );
        }

        // An interval of 0 runs its task back to back, and a timeout of 0 cuts every connection.
        let positive = [
            ("sync_interval_secs", config.sync_interval_secs),
            ("idle_timeout_secs", config.idle_timeout_secs),
            ("request_timeout_secs", config.request_timeout_secs),
            ("gc.interval_secs", config.gc.interval_secs),
        ];
        if let Some((name, _)) = positive.iter().find(|(_, value)| *value == 0) {
            bail!("{}: {name} is 0, it must be at least 1", path.display());
        }

        let base = path.parent().unwrap_or(Path::new("."));
        config.data_dir = base.join(&config.data_dir);
        config.repo_key = base.join(&config.repo_key);
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

    /// Refuses a configuration whose [[keys]] do not fit `source`: one source of keys only.
    pub fn check_keys(&self, source: KeySource) -> Result<()> {
        if self
            .keys
            .iter()
            .any(|k| k.access_key.is_empty() || k.secret_key.expose().is_empty())
        {
            bail!("a [[keys]] entry has an empty access_key or secret_key");
        }
        match (source, self.keys.is_empty()) {
            (KeySource::Config, true) => {
                bail!("the configuration needs at least one [[keys]] entry")
            }
            (KeySource::Store, false) => bail!(
                "the configuration has [[keys]] entries and a key store gives the keys: remove \
                 the [[keys]] entries"
            ),
            _ => Ok(()),
        }
    }

    pub fn keys(&self) -> HashMap<String, String> {
        self.keys
            .iter()
            .map(|k| (k.access_key.clone(), k.secret_key.expose().to_string()))
            .collect()
    }

    pub fn engine(&self) -> engine::Config {
        engine::Config {
            cache_bytes: self.engine.cache_bytes,
            flush_delay: Duration::from_millis(self.engine.flush_delay_ms),
            buffer_limit: self.engine.buffer_limit_bytes,
            read_budget: self.engine.read_budget_bytes,
            read_ahead: self.engine.read_ahead,
            copy_ref_min: self.engine.copy_ref_min,
            gc_horizon: Duration::from_secs(self.gc.horizon_secs),
            retention: Duration::from_secs(self.gc.retention_secs),
            late_margin: Duration::from_secs(self.gc.late_margin_secs),
            snapshot_interval: Duration::from_secs(self.gc.snapshot_interval_secs),
            retire_chains: self.gc.retire_chains,
            ..engine::Config::default()
        }
    }

    /// A configuration for one local proxy: a remote directory next to the data, and a fresh key pair.
    pub fn local() -> Result<Self> {
        Ok(Self {
            data_dir: PathBuf::from("data"),
            repo_key: default_repo_key(),
            listen: default_listen(),
            remote: RemoteConfig::Dir {
                path: PathBuf::from("remote"),
            },
            keys: vec![KeyConfig {
                access_key: format!(
                    "WS{}",
                    random_chars(18, b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")?
                ),
                secret_key: Secret(hex::encode(random_bytes::<20>()?)),
            }],
            sync_interval_secs: default_sync_interval(),
            max_connections: None,
            idle_timeout_secs: default_idle_timeout(),
            request_timeout_secs: default_request_timeout(),
            uploads_expire_secs: default_uploads_expire(),
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
        assert_eq!(config.keys[0].secret_key.expose().len(), 40);
        assert!(!format!("{config:?}").contains(config.keys[0].secret_key.expose()));
        assert_ne!(Config::local().unwrap().keys, config.keys);
    }

    #[test]
    fn test_paths_are_relative_to_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("windsock.toml");
        std::fs::write(&path, toml::to_string(&Config::local().unwrap()).unwrap()).unwrap();

        let config = Config::load(&path).unwrap();

        assert_eq!(config.data_dir, dir.path().join("data"));
        assert_eq!(config.repo_key, dir.path().join("repo.key"));
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
    fn test_snapshot_interval_reaches_the_engine() {
        let base = "data_dir = \"d\"\n[remote]\ntype = \"dir\"\npath = \"r\"\n\
                    [[keys]]\naccess_key = \"c\"\nsecret_key = \"d\"\n";

        let set: Config =
            toml::from_str(&format!("{base}[gc]\nsnapshot_interval_secs = 60\n")).unwrap();
        let default: Config = toml::from_str(base).unwrap();

        assert_eq!(set.engine().snapshot_interval, Duration::from_secs(60));
        assert_eq!(
            default.engine().snapshot_interval,
            Duration::from_secs(86_400)
        );
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
    fn test_unknown_field_is_rejected() {
        assert!(toml::from_str::<Config>("data_dir = \"d\"\nlisten_on = \"x\"").is_err());
    }

    #[test]
    fn test_keys_come_from_one_source_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("windsock.toml");
        std::fs::write(
            &path,
            "data_dir = \"d\"\n[remote]\ntype = \"dir\"\npath = \"r\"\n",
        )
        .unwrap();
        let without = Config::load(&path).unwrap();
        let with = Config::local().unwrap();

        assert!(without.check_keys(KeySource::Config).is_err());
        assert!(without.check_keys(KeySource::Store).is_ok());
        assert!(with.check_keys(KeySource::Config).is_ok());
        assert!(with.check_keys(KeySource::Store).is_err());
    }

    #[test]
    fn test_empty_access_key_or_secret_is_refused() {
        let key = |access: &str, secret: &str| {
            let mut config = Config::local().unwrap();
            config.keys = vec![KeyConfig {
                access_key: access.into(),
                secret_key: Secret(secret.into()),
            }];
            config
        };

        assert!(key("", "secret").check_keys(KeySource::Config).is_err());
        assert!(key("AKID", "").check_keys(KeySource::Config).is_err());
        assert!(key("AKID", "secret").check_keys(KeySource::Config).is_ok());
    }

    #[test]
    fn test_upload_expiry_under_one_hour_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("windsock.toml");
        let config = Config::local().unwrap();
        let mut text = toml::to_string(&config).unwrap();
        text = text.replace("uploads_expire_secs = 604800", "uploads_expire_secs = 0");
        std::fs::write(&path, text).unwrap();

        let error = Config::load(&path).unwrap_err().to_string();

        assert!(error.contains("uploads_expire_secs"), "{error}");
    }

    #[test]
    fn test_zero_interval_or_timeout_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("windsock.toml");
        let text = toml::to_string(&Config::local().unwrap()).unwrap();
        let fields = [
            "sync_interval_secs",
            "idle_timeout_secs",
            "request_timeout_secs",
            "interval_secs",
        ];

        for field in fields {
            let line = text
                .lines()
                .find(|line| line.starts_with(&format!("{field} = ")))
                .unwrap();
            std::fs::write(&path, text.replace(line, &format!("{field} = 0"))).unwrap();
            let loaded = Config::load(&path);

            let error = loaded.err().map(|e| e.to_string()).unwrap_or_default();
            assert!(error.contains(field), "{field}: {error}");
        }
    }
}
