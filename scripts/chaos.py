#!/usr/bin/env python3
"""Chaos soak: 3 windsockd processes on one directory remote, mixed S3 traffic, kills and restarts.

Usage (macOS, needs boto3 and hdiutil):

    cargo build --release -p windsockd
    python3 scripts/chaos.py --minutes 10 --work /tmp/ws-chaos

The script prints one line per phase and a summary. It exits 1 when a check fails.
"""

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError, BotoCoreError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "target", "release", "windsockd")
BUCKET = "chaos"
PORTS = [9101, 9102, 9103]
HORIZON = 20
WORKERS = 6
GONE = None


def log(*args):
    print(time.strftime("%H:%M:%S"), *args, flush=True)


class Proxy:
    def __init__(self, n, work):
        self.n = n
        self.dir = os.path.join(work, f"p{n}")
        self.config = os.path.join(self.dir, "windsock.toml")
        self.log_path = os.path.join(work, f"p{n}.log")
        self.proc = None
        self.lock = threading.Lock()
        self.access = self.secret = None
        self.client = None

    def start(self):
        with self.lock:
            out = open(self.log_path, "a")
            out.write(f"\n==== start {time.time():.0f}\n")
            out.flush()
            env = dict(os.environ, RUST_LOG="info")
            self.proc = subprocess.Popen([BIN, "run", self.config], stdout=out, stderr=out, env=env)
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                self.client.list_buckets()
                return
            except Exception:
                if self.proc.poll() is not None:
                    raise RuntimeError(f"p{self.n} exited at start: see {self.log_path}")
                time.sleep(0.2)
        raise RuntimeError(f"p{self.n} did not listen")

    def signal(self, sig):
        with self.lock:
            if self.proc and self.proc.poll() is None:
                self.proc.send_signal(sig)

    def wait(self, limit):
        try:
            self.proc.wait(limit)
            return True
        except subprocess.TimeoutExpired:
            return False

    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def fds(self):
        """Open files of the daemon, counted by kind."""
        out = subprocess.run(["lsof", "-n", "-P", "-p", str(self.proc.pid)], capture_output=True, text=True)
        kinds = {}
        for line in out.stdout.splitlines()[1:]:
            cols = line.split(None, 8)
            if len(cols) < 9 or not cols[3][:1].isdigit():
                continue
            kind, name = cols[4], cols[8]
            if kind in ("IPv4", "IPv6"):
                label = "socket listen" if "LISTEN" in name else "socket tcp"
            elif kind in ("PIPE", "KQUEUE", "unix", "systm"):
                label = kind.lower()
            elif "/buffer/" in name:
                label = "buffer"
            elif "/index/" in name:
                label = "index"
            elif "/cache/" in name:
                label = "cache"
            elif "/remote/" in name:
                label = "remote"
            elif "/uploads/" in name:
                label = "uploads"
            else:
                label = "other " + kind
            kinds[label] = kinds.get(label, 0) + 1
        return kinds

    def usage(self):
        pid = str(self.proc.pid)
        rss = subprocess.run(["ps", "-o", "rss=", "-p", pid], capture_output=True, text=True).stdout.strip()
        fds = subprocess.run(["lsof", "-p", pid], capture_output=True, text=True).stdout.count("\n")
        return int(rss or 0) // 1024, fds


MARKER = ".windsock-chaos"


def setup(work):
    # Remove only a directory that this script made: the marker file proves it.
    if os.path.exists(work):
        if os.listdir(work) and not os.path.exists(os.path.join(work, MARKER)):
            raise SystemExit(f"{work} is not empty and has no {MARKER} file: choose another --work")
        shutil.rmtree(work)
    os.makedirs(work)
    open(os.path.join(work, MARKER), "w").close()
    remote = os.path.join(work, "remote")
    proxies = [Proxy(n, work) for n in range(3)]
    for p in proxies:
        subprocess.run([BIN, "init", p.dir], check=True, capture_output=True)
    shutil.copy(os.path.join(proxies[0].dir, "repo.key"), os.path.join(work, "repo.key"))
    os.chmod(os.path.join(work, "repo.key"), 0o600)

    for p, port in zip(proxies, PORTS):
        text = open(p.config).read()
        p.access = re.search(r'access_key = "([^"]+)"', text).group(1)
        p.secret = re.search(r'secret_key = "([^"]+)"', text).group(1)
        text = re.sub(r'(?m)^repo_key = .*$', f'repo_key = "{work}/repo.key"', text)
        text = re.sub(r'(?m)^listen = .*$', f'listen = "127.0.0.1:{port}"', text)
        text = re.sub(r'(?ms)^\[remote\].*?(?=^\[)', f'[remote]\ntype = "dir"\npath = "{remote}"\n\n', text)
        text = re.sub(r'(?m)^sync_interval_secs = .*$', "sync_interval_secs = 1", text)
        text = re.sub(r'(?m)^cache_bytes = .*$', f"cache_bytes = {8 << 20}", text)
        text = re.sub(r'(?m)^flush_delay_ms = .*$', "flush_delay_ms = 300", text)
        text = re.sub(r'(?m)^buffer_limit_bytes = .*$', f"buffer_limit_bytes = {64 << 20}", text)
        text = re.sub(r'(?m)^enabled = .*$', f"enabled = {'true' if p.n == 0 else 'false'}", text)
        text = re.sub(r'(?m)^interval_secs = .*$', "interval_secs = 5", text)
        text = re.sub(r'(?m)^horizon_secs = .*$', f"horizon_secs = {HORIZON}", text)
        text = re.sub(r'(?m)^retention_secs = .*$', "retention_secs = 40", text)
        text = re.sub(r'(?m)^late_margin_secs = .*$', "late_margin_secs = 10", text)
        text = re.sub(r'(?m)^snapshot_interval_secs = .*$', "snapshot_interval_secs = 15", text)
        open(p.config, "w").write(text)
        p.client = boto3.client(
            "s3",
            endpoint_url=f"http://127.0.0.1:{port}",
            region_name="us-east-1",
            aws_access_key_id=p.access,
            aws_secret_access_key=p.secret,
            config=BotoConfig(
                s3={"addressing_style": "path"},
                retries={"max_attempts": 1, "mode": "standard"},
                connect_timeout=3,
                read_timeout=30,
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )
    return proxies


class Model:
    """For each key, the values that a client may read back: acked writes give one, unknown give more."""

    def __init__(self):
        self.lock = threading.Lock()
        self.allowed = {}
        self.stats = {"acked": 0, "refused": 0, "unknown": 0, "ops": 0}

    def outcome(self, key, value, result):
        with self.lock:
            self.stats["ops"] += 1
            prev = self.allowed.get(key, {GONE})
            if result == "acked":
                self.allowed[key] = {value}
                self.stats["acked"] += 1
            elif result == "unknown":
                self.allowed[key] = prev | {value}
                self.stats["unknown"] += 1
            else:
                self.stats["refused"] += 1


def classify(error):
    if isinstance(error, ClientError):
        status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
        return "refused" if 400 <= status < 500 or status == 503 else "unknown"
    return "unknown"


def digest(data):
    return hashlib.blake2b(data, digest_size=16).hexdigest()


def full_disk(p, sub, work, image_mb, seconds):
    """Runs p with data/engine/<sub> on a small disk image for `seconds`, then moves it back."""
    target = os.path.join(p.dir, "data", "engine", sub)
    image = os.path.join(work, f"{sub}.dmg")
    mount = os.path.join(work, f"{sub}-mnt")
    p.signal(signal.SIGTERM)
    p.wait(90)
    subprocess.run(
        ["hdiutil", "create", "-size", f"{image_mb}m", "-fs", "HFS+", "-volname", sub, "-ov", image],
        check=True, capture_output=True,
    )
    os.makedirs(mount, exist_ok=True)
    subprocess.run(["hdiutil", "attach", image, "-mountpoint", mount, "-nobrowse"], check=True, capture_output=True)
    for name in os.listdir(target):
        shutil.move(os.path.join(target, name), os.path.join(mount, name))
    os.rmdir(target)
    os.symlink(mount, target)
    p.start()
    filler = os.path.join(mount, "filler")
    with open(filler, "wb") as f:
        try:
            while True:
                f.write(b"\0" * (1 << 20))
                f.flush()
        except OSError:
            pass
    time.sleep(seconds)
    os.remove(filler)
    time.sleep(2)
    p.signal(signal.SIGTERM)
    if not p.wait(90):
        p.signal(signal.SIGKILL)
        p.wait(30)
    os.remove(target)
    os.makedirs(target)
    # rsync skips the volume files, and a file that vanishes during the copy is not fatal.
    subprocess.run(
        ["rsync", "-a", "--exclude", ".Spotlight-V100", "--exclude", ".fseventsd", "--exclude", ".Trashes",
         mount + "/", target + "/"],
        capture_output=True,
    )
    subprocess.run(["hdiutil", "detach", mount, "-force"], capture_output=True)
    p.start()


def worker(w, proxies, model, stop, rng):
    n = 0
    while not stop.is_set():
        p = rng.choice(proxies)
        if not p.running():
            time.sleep(0.05)
            continue
        key = f"w{w}/k{rng.randrange(40)}"
        op = rng.choices(["put", "get", "delete", "list", "multipart", "range"], [40, 20, 10, 10, 5, 15])[0]
        try:
            if op == "put":
                size = rng.choice([0, 1, 100, 4096, 65536, 300_000, 2_000_000])
                data = rng.randbytes(size)
                try:
                    p.client.put_object(Bucket=BUCKET, Key=key, Body=data)
                    model.outcome(key, digest(data), "acked")
                except (ClientError, BotoCoreError) as e:
                    model.outcome(key, digest(data), classify(e))
            elif op == "delete":
                try:
                    p.client.delete_object(Bucket=BUCKET, Key=key)
                    model.outcome(key, GONE, "acked")
                except (ClientError, BotoCoreError) as e:
                    model.outcome(key, GONE, classify(e))
            elif op == "multipart":
                parts = [rng.randbytes(rng.choice([1, 70_000, 1_100_000])) for _ in range(rng.randint(1, 3))]
                data = b"".join(parts)
                try:
                    up = p.client.create_multipart_upload(Bucket=BUCKET, Key=key)["UploadId"]
                    done = []
                    for i, part in enumerate(parts, 1):
                        r = p.client.upload_part(Bucket=BUCKET, Key=key, UploadId=up, PartNumber=i, Body=part)
                        done.append({"PartNumber": i, "ETag": r["ETag"]})
                except (ClientError, BotoCoreError):
                    continue
                try:
                    p.client.complete_multipart_upload(
                        Bucket=BUCKET, Key=key, UploadId=up, MultipartUpload={"Parts": done}
                    )
                    model.outcome(key, digest(data), "acked")
                except (ClientError, BotoCoreError) as e:
                    model.outcome(key, digest(data), classify(e))
            elif op == "get":
                p.client.get_object(Bucket=BUCKET, Key=key)["Body"].read()
            elif op == "range":
                p.client.get_object(Bucket=BUCKET, Key=key, Range="bytes=10-5000")["Body"].read()
            else:
                p.client.list_objects_v2(Bucket=BUCKET, Prefix=f"w{w}/", MaxKeys=7)
        except (ClientError, BotoCoreError):
            pass
        n += 1


def restart(p, sig, down):
    p.signal(sig)
    if not p.wait(90):
        p.signal(signal.SIGKILL)
        p.wait(30)
    time.sleep(down)
    p.start()


def faults(proxies, stop, rng, counts, pause):
    while not stop.wait(rng.uniform(8, 25)):
        p = rng.choice(proxies)
        sig = rng.choice([signal.SIGKILL, signal.SIGKILL, signal.SIGTERM])
        name = "KILL" if sig == signal.SIGKILL else "TERM"
        with pause:
            if not p.running():
                continue
            log(f"fault: {name} p{p.n}")
            try:
                restart(p, sig, rng.uniform(0.5, 4))
            except RuntimeError as e:
                log(f"restart failed: {e}")
                counts["failed_restart"] = counts.get("failed_restart", 0) + 1
                continue
            counts[name] += 1


def monitor(proxies, stop, samples):
    while not stop.wait(30):
        row = {}
        for p in proxies:
            if p.running():
                row[p.n] = p.usage()
        samples.append((time.time(), row))
        log("usage (MiB, fds):", row)
        for p in proxies:
            if p.running():
                log(f"fds p{p.n}:", json.dumps(p.fds(), sort_keys=True))


def converge(proxies, model):
    """Every proxy shows an allowed value for each key, and all three show the same one."""
    for p in proxies:
        if not p.running():
            p.start()
    keys = sorted(model.allowed)
    deadline = time.time() + 180
    while True:
        bad = []
        for key in keys:
            seen = []
            for p in proxies:
                try:
                    data = p.client.get_object(Bucket=BUCKET, Key=key)["Body"].read()
                    seen.append(digest(data))
                except ClientError as e:
                    code = e.response["Error"]["Code"]
                    seen.append(GONE if code == "NoSuchKey" else f"error {code}")
            if len(set(seen)) != 1 or seen[0] not in model.allowed[key]:
                bad.append((key, seen, sorted(map(str, model.allowed[key]))))
        if not bad or time.time() > deadline:
            return keys, bad
        time.sleep(5)


def grep_logs(proxies, patterns):
    hits = {}
    for p in proxies:
        text = open(p.log_path, errors="replace").read()
        for pat in patterns:
            found = [line for line in text.splitlines() if pat in line]
            if found:
                hits.setdefault(f"p{p.n}: {pat}", []).extend(found[:3])
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=10)
    ap.add_argument("--work", default="/tmp/ws-chaos")
    ap.add_argument("--image-mb", type=int, default=64)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    proxies = setup(args.work)
    try:
        for p in proxies:
            p.start()
        proxies[0].client.create_bucket(Bucket=BUCKET)
        time.sleep(3)

        model = Model()
        stop = threading.Event()
        threads = [
            threading.Thread(target=worker, args=(w, proxies, model, stop, random.Random(args.seed * 100 + w)))
            for w in range(WORKERS)
        ]
        samples = []
        counts = {"KILL": 0, "TERM": 0}
        pause = threading.Lock()
        threads.append(threading.Thread(target=faults, args=(proxies, stop, rng, counts, pause)))
        threads.append(threading.Thread(target=monitor, args=(proxies, stop, samples)))
        start = time.time()
        for t in threads:
            t.start()

        total = args.minutes * 60
        time.sleep(total * 0.25)
        for sub in ["buffer", "index"]:
            log(f"phase: p2 with a full disk under data/engine/{sub} for 10 s")
            with pause:
                full_disk(proxies[2], sub, args.work, args.image_mb, 10)
            log(f"phase: p2 back from the full {sub} disk")
        time.sleep(max(0, total * 0.5 - (time.time() - start)))
        log(f"phase: p1 stops for {2 * HORIZON} s, longer than H")
        with pause:
            proxies[1].signal(signal.SIGTERM)
            proxies[1].wait(90)
        time.sleep(2 * HORIZON)
        with pause:
            proxies[1].start()
        log("phase: p1 back")
        time.sleep(max(0, total - (time.time() - start)))

        stop.set()
        for t in threads:
            t.join()
        log("load stopped; ops", model.stats, "faults", counts)
        time.sleep(15)

        keys, bad = converge(proxies, model)
        time.sleep(12)
        hits = grep_logs(
            proxies,
            ["chain is broken", "Gap", "Changed", "panicked", "broken chains", "differs from the copy"],
        )
        usage = [(round(t - start), row) for t, row in samples]
        result = {
            "keys": len(keys),
            "bad": bad[:10],
            "bad_count": len(bad),
            "ops": model.stats,
            "faults": counts,
            "log_hits": hits,
            "usage": usage,
        }
        print("RESULT", json.dumps(result, default=str))
        return 1 if bad or hits else 0
    finally:
        for p in proxies:
            p.signal(signal.SIGTERM)
        for p in proxies:
            if p.proc:
                p.wait(60)


if __name__ == "__main__":
    sys.exit(main())
