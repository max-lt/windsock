//! One windsockd process: its configuration, start, signals, open files and full disk phase.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, kill_process};

use crate::s3::S3;

pub const BUCKET: &str = "chaos";
/// H of the soak, in seconds: short, so that the GC deletes during the run.
pub const HORIZON: u64 = 20;
const PORTS: [u16; 3] = [9101, 9102, 9103];
/// A work directory holds this file once the soak made it: only such a directory is removed.
const MARKER: &str = ".windsock-chaos";

pub struct Proxy {
    pub n: usize,
    dir: PathBuf,
    config: PathBuf,
    pub log: PathBuf,
    bin: PathBuf,
    child: Mutex<Option<Child>>,
    pub s3: S3,
}

/// Makes the work directory and the configurations of 3 proxies on one directory remote.
pub fn setup(work: &Path, bin: &Path) -> Result<Vec<Proxy>, String> {
    if work.exists() {
        let empty = std::fs::read_dir(work)
            .map_err(|e| e.to_string())?
            .next()
            .is_none();
        if !empty && !work.join(MARKER).exists() {
            return Err(format!(
                "{} is not empty and has no {MARKER} file: choose another --work",
                work.display()
            ));
        }
        std::fs::remove_dir_all(work).map_err(|e| e.to_string())?;
    }
    std::fs::create_dir_all(work).map_err(|e| e.to_string())?;
    std::fs::write(work.join(MARKER), b"").map_err(|e| e.to_string())?;
    let remote = work.join("remote");
    let repo_key = work.join("repo.key");

    let mut proxies = Vec::new();
    for (n, port) in PORTS.iter().enumerate() {
        let dir = work.join(format!("p{n}"));
        let status = Command::new(bin)
            .arg("init")
            .arg(&dir)
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("cannot run {}: {e}", bin.display()))?;
        if !status.success() {
            return Err(format!("windsockd init {} failed", dir.display()));
        }
        if n == 0 {
            std::fs::copy(dir.join("repo.key"), &repo_key).map_err(|e| e.to_string())?;
        }
        let config = dir.join("windsock.toml");
        let text = std::fs::read_to_string(&config).map_err(|e| e.to_string())?;
        let value = |name: &str| {
            text.lines()
                .find(|line| line.starts_with(name))
                .and_then(|line| line.split('"').nth(1))
                .map(str::to_string)
                .ok_or(format!("no {name} in {}", config.display()))
        };
        let (access, secret) = (value("access_key")?, value("secret_key")?);
        let text = configure(&text, n, *port, &remote, &repo_key);
        std::fs::write(&config, text).map_err(|e| e.to_string())?;
        proxies.push(Proxy {
            n,
            dir,
            config,
            log: work.join(format!("p{n}.log")),
            bin: bin.to_path_buf(),
            child: Mutex::new(None),
            s3: S3::new(&format!("127.0.0.1:{port}"), &access, &secret),
        });
    }
    Ok(proxies)
}

/// The soak settings: short H, R and M, a small cache and buffer, the GC on proxy 0 only.
fn configure(text: &str, n: usize, port: u16, remote: &Path, repo_key: &Path) -> String {
    let set = [
        ("repo_key", format!("\"{}\"", repo_key.display())),
        ("listen", format!("\"127.0.0.1:{port}\"")),
        ("sync_interval_secs", "1".to_string()),
        ("cache_bytes", (8u64 << 20).to_string()),
        ("flush_delay_ms", "300".to_string()),
        ("buffer_limit_bytes", (64u64 << 20).to_string()),
        ("enabled", (n == 0).to_string()),
        ("interval_secs", "5".to_string()),
        ("horizon_secs", HORIZON.to_string()),
        ("retention_secs", "40".to_string()),
        ("late_margin_secs", "10".to_string()),
        ("snapshot_interval_secs", "15".to_string()),
    ];
    let mut out = String::new();
    let mut in_remote = false;
    for line in text.lines() {
        if line.starts_with('[') {
            in_remote = line == "[remote]";
            out.push_str(line);
            out.push('\n');
            if in_remote {
                out.push_str(&format!(
                    "type = \"dir\"\npath = \"{}\"\n",
                    remote.display()
                ));
            }
            continue;
        }
        if in_remote {
            continue;
        }
        let name = line.split(" = ").next().unwrap_or("");
        match set.iter().find(|(key, _)| *key == name) {
            Some((key, value)) => out.push_str(&format!("{key} = {value}\n")),
            None => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

impl Proxy {
    /// Starts the daemon and waits until it answers S3 calls.
    pub async fn start(&self) -> Result<(), String> {
        {
            let mut log = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log)
                .map_err(|e| e.to_string())?;
            writeln!(log, "\n==== start").map_err(|e| e.to_string())?;
            let child = Command::new(&self.bin)
                .arg("run")
                .arg(&self.config)
                .env("RUST_LOG", "info")
                .stdout(log.try_clone().map_err(|e| e.to_string())?)
                .stderr(log)
                .spawn()
                .map_err(|e| e.to_string())?;
            *self.child.lock().expect("no panic while the lock is held") = Some(child);
        }
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            if self.s3.get("/").await.is_ok() {
                return Ok(());
            }
            if !self.running() {
                return Err(format!(
                    "p{} exited at start: see {}",
                    self.n,
                    self.log.display()
                ));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Err(format!("p{} did not listen", self.n))
    }

    pub fn pid(&self) -> Option<u32> {
        let child = self.child.lock().expect("no panic while the lock is held");
        child.as_ref().map(Child::id)
    }

    pub fn running(&self) -> bool {
        let mut child = self.child.lock().expect("no panic while the lock is held");
        child
            .as_mut()
            .is_some_and(|child| child.try_wait().is_ok_and(|status| status.is_none()))
    }

    pub fn signal(&self, signal: Signal) {
        if !self.running() {
            return;
        }
        let pid = self.pid().and_then(|pid| Pid::from_raw(pid as i32));
        if let Some(pid) = pid {
            let _ = kill_process(pid, signal);
        }
    }

    /// Waits up to `limit` for the process to end. True when it ended.
    pub async fn wait(&self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if !self.running() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        !self.running()
    }

    /// A stop with `signal`, a KILL when it does not end, a pause, and a start.
    pub async fn restart(&self, signal: Signal, down: Duration) -> Result<(), String> {
        self.stop(signal).await;
        tokio::time::sleep(down).await;
        self.start().await
    }

    pub async fn stop(&self, signal: Signal) {
        self.signal(signal);
        if !self.wait(Duration::from_secs(90)).await {
            self.signal(Signal::KILL);
            self.wait(Duration::from_secs(30)).await;
        }
    }

    /// Resident memory in MiB and open files, or `None` when the process is not running.
    pub fn usage(&self) -> Option<(u64, BTreeMap<String, u64>)> {
        let pid = self.pid()?.to_string();
        let rss = Command::new("ps")
            .args(["-o", "rss=", "-p", &pid])
            .output()
            .ok()?;
        let rss: u64 = String::from_utf8_lossy(&rss.stdout)
            .trim()
            .parse()
            .unwrap_or(0);
        let lsof = Command::new("lsof")
            .args(["-n", "-P", "-p", &pid])
            .output()
            .ok()?;
        Some((rss / 1024, fd_kinds(&String::from_utf8_lossy(&lsof.stdout))))
    }

    /// Runs this proxy with `data/engine/<sub>` on a small disk image, full for `hold`, then
    /// moves the directory back.
    pub async fn full_disk(
        &self,
        sub: &str,
        work: &Path,
        image_mb: u64,
        hold: Duration,
    ) -> Result<(), String> {
        let target = self.dir.join("data").join("engine").join(sub);
        let image = work.join(format!("{sub}.dmg"));
        let mount = work.join(format!("{sub}-mnt"));
        self.stop(Signal::TERM).await;
        let used = dir_size(&target) >> 20;
        let size = image_mb.max(used + image_mb);
        let image_arg = image.to_string_lossy().into_owned();
        let mount_arg = mount.to_string_lossy().into_owned();
        run(&[
            "hdiutil",
            "create",
            "-size",
            &format!("{size}m"),
            "-fs",
            "HFS+",
            "-volname",
            sub,
            "-ov",
            &image_arg,
        ])?;
        std::fs::create_dir_all(&mount).map_err(|e| e.to_string())?;
        run(&[
            "hdiutil",
            "attach",
            &image_arg,
            "-mountpoint",
            &mount_arg,
            "-nobrowse",
        ])?;
        let target_arg = format!("{}/", target.display());
        run(&["rsync", "-a", &target_arg, &format!("{mount_arg}/")])?;
        std::fs::remove_dir_all(&target).map_err(|e| e.to_string())?;
        std::os::unix::fs::symlink(&mount, &target).map_err(|e| e.to_string())?;
        self.start().await?;

        let filler = mount.join("filler");
        if let Ok(mut file) = std::fs::File::create(&filler) {
            let block = vec![0u8; 1 << 20];
            while file.write_all(&block).and_then(|()| file.flush()).is_ok() {}
        }
        tokio::time::sleep(hold).await;
        let _ = std::fs::remove_file(&filler);
        tokio::time::sleep(Duration::from_secs(2)).await;
        self.stop(Signal::TERM).await;

        std::fs::remove_file(&target).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&target).map_err(|e| e.to_string())?;
        // The volume files stay, and a file that goes during the copy does not stop it.
        let _ = Command::new("rsync")
            .args([
                "-a",
                "--exclude",
                ".Spotlight-V100",
                "--exclude",
                ".fseventsd",
            ])
            .args([
                "--exclude",
                ".Trashes",
                &format!("{mount_arg}/"),
                &target_arg,
            ])
            .output();
        let _ = Command::new("hdiutil")
            .args(["detach", &mount_arg, "-force"])
            .output();
        self.start().await
    }
}

fn run(args: &[&str]) -> Result<(), String> {
    let output = Command::new(args[0])
        .args(&args[1..])
        .output()
        .map_err(|e| format!("{}: {e}", args[0]))?;
    match output.status.success() {
        true => Ok(()),
        false => Err(format!(
            "{}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )),
    }
}

fn dir_size(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| match entry.file_type() {
            Ok(kind) if kind.is_dir() => dir_size(&entry.path()),
            _ => entry.metadata().map_or(0, |m| m.len()),
        })
        .sum()
}

/// The open files in an lsof listing, counted by kind.
fn fd_kinds(lsof: &str) -> BTreeMap<String, u64> {
    let mut kinds = BTreeMap::new();
    for line in lsof.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 9 || !cols[3].starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        let (kind, name) = (cols[4], cols[8..].join(" "));
        let label = match kind {
            "IPv4" | "IPv6" if name.contains("LISTEN") => "socket listen".to_string(),
            "IPv4" | "IPv6" => "socket tcp".to_string(),
            "PIPE" | "KQUEUE" | "unix" | "systm" => kind.to_lowercase(),
            _ if name.contains("/buffer/") => "buffer".to_string(),
            _ if name.contains("/index/") => "index".to_string(),
            _ if name.contains("/cache/") => "cache".to_string(),
            _ if name.contains("/remote/") => "remote".to_string(),
            _ if name.contains("/uploads/") => "uploads".to_string(),
            _ => format!("other {kind}"),
        };
        *kinds.entry(label).or_insert(0) += 1;
    }
    kinds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_configure_sets_the_soak_values_and_the_remote() {
        let text = "data_dir = \"data\"\nlisten = \"127.0.0.1:9000\"\n\n[remote]\ntype = \"dir\"\n\
                    path = \"remote\"\n\n[gc]\nenabled = false\nhorizon_secs = 86400\n";

        let out = configure(
            text,
            0,
            9101,
            Path::new("/w/remote"),
            Path::new("/w/repo.key"),
        );

        assert!(out.contains("listen = \"127.0.0.1:9101\""), "{out}");
        assert!(
            out.contains("[remote]\ntype = \"dir\"\npath = \"/w/remote\"\n[gc]"),
            "{out}"
        );
        assert!(out.contains("enabled = true"), "{out}");
        assert!(out.contains("horizon_secs = 20"), "{out}");
        assert!(out.contains("data_dir = \"data\""), "{out}");
    }

    #[test]
    fn test_fd_kinds_counts_by_kind() {
        let lsof = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n\
                    w 1 m 3u IPv4 0x1 0t0 TCP 127.0.0.1:9101 (LISTEN)\n\
                    w 1 m 4u REG 1,2 10 5 /d/data/engine/buffer/00000000000000000001.log\n\
                    w 1 m cwd DIR 1,2 10 5 /d\n";

        let kinds = fd_kinds(lsof);

        assert_eq!(kinds["socket listen"], 1);
        assert_eq!(kinds["buffer"], 1);
        assert_eq!(kinds.len(), 2);
    }
}
