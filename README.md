# Windsock

Windsock is an S3-compatible proxy and cache. It keeps the data in a remote store: a local
directory or an S3-compatible bucket. The remote holds the only durable copy of the data.

## Run it locally

You need a Rust toolchain (`cargo`) and `curl` 7.75 or later. The steps take about 5 minutes.
Most of that time is the first build (under a minute on an M-series Mac).

1. Build the daemon.

   ```bash
   cargo build --release -p windsockd
   ```

2. Make a configuration. This writes `./local/windsock.toml` with a new access key and secret, and
   `./local/repo.key`, the secret of the remote. Keep a copy of `repo.key` away from the remote:
   without it, nobody can read the data.
   The remote is the directory `./local/remote`. The file is readable by you only.

   ```bash
   ./target/release/windsockd init ./local
   ```

3. Start the daemon. It serves S3 on `http://127.0.0.1:9000`. Keep this terminal open.

   ```bash
   ./target/release/windsockd run ./local/windsock.toml
   ```

4. In a second terminal, read the key pair from the configuration, and make a signed `curl`.
   The function works in zsh and bash.

   ```bash
   AK=$(grep access_key local/windsock.toml | cut -d'"' -f2)
   SK=$(grep secret_key local/windsock.toml | cut -d'"' -f2)
   s3() { curl -sS --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" "$@"; }
   ```

5. Make a bucket, write a file, read it back.

   ```bash
   s3 -X PUT http://127.0.0.1:9000/demo
   echo "hello windsock" > hello.txt
   s3 -T hello.txt http://127.0.0.1:9000/demo/hello.txt
   s3 http://127.0.0.1:9000/demo/hello.txt
   s3 "http://127.0.0.1:9000/demo?list-type=2"
   ```

6. Stop the daemon with Ctrl-C or SIGTERM. From that signal, the daemon answers writes with 503
   ServiceUnavailable and `Retry-After: 5`, and serves reads. It writes the buffered data to the
   remote, then stops. While the remote fails, it tries again every 5 s, logs one warning a
   minute, and does not stop. A second signal stops it at once: the buffered data stays on the
   local disk and goes to the remote at the next start. Give the service manager a stop timeout
   long enough for the buffer to upload (systemd `TimeoutStopSec`). A signal during the replay at
   start ends the process at once. The next start replays the buffer again.

### Other S3 clients

Use the endpoint `http://127.0.0.1:9000`, the region `us-east-1`, path-style addressing, and the
key pair from step 4.

- AWS CLI: `aws --endpoint-url http://127.0.0.1:9000 s3 ls s3://demo/`
- boto3: `boto3.client("s3", endpoint_url="http://127.0.0.1:9000", region_name="us-east-1",
aws_access_key_id=AK, aws_secret_access_key=SK, config=Config(s3={"addressing_style": "path"}))`

## Run it under a supervisor

Run `windsockd` under a service manager that restarts it when it exits with status 1. The daemon
exits with status 1 when its local index refuses every call after a failed write, often a full
disk: the buffer is on disk, and the next start flushes it. With systemd:

```ini
[Service]
ExecStart=/usr/local/bin/windsockd run /etc/windsock/windsock.toml
Restart=on-failure
RestartSec=5
# Time for the buffer to upload at stop.
TimeoutStopSec=600
LimitNOFILE=65536
```

The proxy with `gc.enabled` deletes an object only after H (24 h by default) of uptime since it
condemned or first saw it. A GC runner that restarts every day, or more often, never deletes:
give it an uptime of H between restarts. `docs/storage.md` (GC deletes and the clock of the GC
host) gives the reason.

A start that fails, for example on a quarantine or a remote with other rules, fails again at
each restart: read the error, act, then start again.

A start that fails with `the own chain is broken` gives a cause. Only a gap names a key: check
that key in the bucket, and remove it when this proxy did not write it. Do not remove an entry
for an HLC ahead of the clock: fix the clock. `docs/storage.md` (Open refusals) gives each
refusal, its cause and the action.

## Time rules

| Name | Setting               | Default | What it does                                                            |
| ---- | --------------------- | ------- | ----------------------------------------------------------------------- |
| H    | `gc.horizon_secs`     | 24 h    | The GC deletes a dead object H after its condemn                        |
| R    | `gc.retention_secs`   | 24 h    | Old versions stay readable for R; the bound for an HLC ahead of a clock |
| M    | `gc.late_margin_secs` | 1 h     | The clock skew that the late write rule allows                          |

H, R and M are rules of the remote: the first proxy fixes them, and every other proxy must use the
same values. When the remote is down for longer than R - M (23 h by default), the acked writes
that wait in the buffer are older than the late limit. The proxy logs an ERROR with their keys,
stops its flusher and refuses writes. A stop then exits with status 1 and names the bytes
that stay in the buffer. At the next start, only those writes move to
`data/engine/quarantine` and the start fails. To replay a write, write the object again through
the S3 API after the start, from the copy that the client holds: no tool reads the quarantine. To discard the late writes, move the files out of the quarantine.
Then start the proxy: the younger writes flush.

## Encryption

Windsock encrypts all data that it writes to the remote with the key in `repo.key`. Back up that
file: without it, nobody can read the data. `docs/encryption.md` tells how to keep the key, how to
share it between the daemons of a cluster, and what each error means.

## When the write buffer does not open

The write buffer is `data/engine/buffer/<20 digits>.log`. A crash can cut only the last segment:
at start, the proxy drops its torn tail and logs `cut a torn record`. Damage in an older segment
stops the start with an error that names the segment file and the record offset. That segment
holds acknowledged writes that are not in the remote yet. If you move the file out of the buffer
directory, the proxy starts, and the writes in that file are lost. A `.log` file whose name is not
20 digits also stops the start: rename it, or move it out. A gap in the segment numbers is normal,
because the proxy deletes empty segments.

The buffer directory holds a file `format` with the record format (2). A buffer of another
format stops the start with both numbers: start the build that wrote it and let it flush. If the
file is empty or does not read, for example after a power loss, and this build wrote the buffer,
write `2` into it and start again.

If a buffered write is older than `gc.retention_secs - gc.late_margin_secs` when it reaches the
remote, the proxy does not commit it: a newer delete of the key can be gone. The proxy logs an
ERROR with the keys and stops its flusher. At the next start, only those writes move to
`data/engine/quarantine`, and the start fails. The other buffered writes stay.

1. List the late writes. The command reads the local data directory only: it needs no remote and
   no repository key.

   ```bash
   windsockd quarantine list /etc/windsock/windsock.toml
   ```

   Each line gives the file, the record number, the op, the key, the ack HLC, the ack time and the
   size. A control character, a tab, a newline or a backslash in a key shows as `\xNN`.

2. Export the bodies to a new directory, to decide for each key and to keep a copy:

   ```bash
   windsockd quarantine export /etc/windsock/windsock.toml /root/late-writes
   ```

   The directory must not exist. It gets mode 0700, each body goes to `<nnnn>.body` (mode 0600),
   and `index.tsv` lists every record. The bodies are client data in clear text, as in the buffer.

3. For each key that must keep the late value, write the body again through the S3 API after
   step 4. The other late writes are dropped.
4. Move the files out of `data/engine/quarantine`, then start the proxy. The young writes flush.

`docs/storage.md` (Order of writes) gives the details.

If the buffer disk is full or cannot be written, the proxy answers writes with 503 SlowDown and
logs `buffer writes fail` once, and `buffer writes work again` when a write works. The flush
frees the buffer disk as the remote takes the segments. Reads go on.

If the chunk cache disk is full or cannot be written, the proxy logs `cache writes fail, reads go to
the remote` once, and `cache writes work again` when a write works. Reads go on from the remote.

## Configuration

`windsockd init` writes all the settings with their default values. Relative paths are relative to
the configuration file.

| Setting                     | Default                              | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                            |
| --------------------------- | ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `data_dir`                  | `data`                               | Engine state, write buffer, chunk cache, multipart parts, node key                                                                                                                                                                                                                                                                                                                                                                 |
| `repo_key`                  | `repo.key`                           | The secret of the remote: it keys the chunk IDs and encrypts all remote objects. Every proxy of one remote needs the same file                                                                                                                                                                                                                                                                                                     |
| `listen`                    | `127.0.0.1:9000`                     | S3 address                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `max_connections`           | min((soft fd limit - 256) / 2, 4096) | Open S3 connections at most. Above it, new clients wait in the kernel backlog. A connection can hold a socket and a file at once, and the engine keeps 256 descriptors. At start the daemon raises the soft limit to min(hard limit, 8192). It does not start under 512 descriptors, or with a value that needs more than 2 x max_connections + 256                                                                                |
| `idle_timeout_secs`         | `60`                                 | A connection with no request in progress closes after this time                                                                                                                                                                                                                                                                                                                                                                    |
| `request_timeout_secs`      | `300`                                | A body upload that receives no byte for this time is cut. Each byte received starts the time again                                                                                                                                                                                                                                                                                                                                 |
| `uploads_expire_secs`       | `604800` (7 days)                    | A multipart upload with no initiate and no part for this time is removed, with its parts. The check runs every hour. The minimum is 3600. The proxy must also have run for this time since it first saw the upload, so a wall clock step does not remove a fresh upload. A proxy that restarts more often than this never removes an upload: clients list them with ListMultipartUploads and remove them with AbortMultipartUpload |
| `remote.type`               | `dir`                                | `dir` (with `path`) or `s3` (with `endpoint`, `bucket`, `prefix`, `region`, `access_key`, `secret_key`, and `ca_file` for a private CA)                                                                                                                                                                                                                                                                                            |
| `[[keys]]`                  | one new pair                         | Key pairs that S3 clients sign with. Every key reaches every bucket                                                                                                                                                                                                                                                                                                                                                                |
| `sync_interval_secs`        | `10`                                 | How often the proxy reads the writes of other proxies                                                                                                                                                                                                                                                                                                                                                                              |
| `engine.cache_bytes`        | 16 GiB                               | Chunk cache size. `0` turns the cache off                                                                                                                                                                                                                                                                                                                                                                                          |
| `engine.flush_delay_ms`     | `1000`                               | Longest time a write waits in the buffer before it goes to the remote                                                                                                                                                                                                                                                                                                                                                              |
| `engine.buffer_limit_bytes` | 8 GiB                                | Writes fail with `503 SlowDown` above this                                                                                                                                                                                                                                                                                                                                                                                         |
| `engine.parts_limit_bytes`  | 4 GiB                                | The parts of all open multipart uploads together. A part fails with `503 SlowDown` above this, and plain writes go on. Clients free the room with ListMultipartUploads and AbortMultipartUpload, or the expiry removes the uploads                                                                                                                                                                                                 |
| `gc.enabled`                | `false`                              | Set to `true` on one proxy per remote. Windsock does not enforce this: see Limits                                                                                                                                                                                                                                                                                                                                                  |
| `gc.interval_secs`          | `3600`                               | How often the GC runs                                                                                                                                                                                                                                                                                                                                                                                                              |
| `gc.horizon_secs`           | `86400`                              | GC horizon. Use the same value on every proxy of a remote. Keep it far above the time of one flush: under one hour, the daemon logs a warning                                                                                                                                                                                                                                                                                      |
| `gc.retention_secs`         | `86400`                              | Old versions stay readable for this time                                                                                                                                                                                                                                                                                                                                                                                           |
| `gc.late_margin_secs`       | `3600`                               | Clock skew that the late write rule allows. A buffered write older than `retention_secs - late_margin_secs` at its commit goes to quarantine. Must be under `retention_secs`                                                                                                                                                                                                                                                       |
| `gc.snapshot_interval_secs` | `86400`                              | The GC writes a snapshot when the latest one is this old                                                                                                                                                                                                                                                                                                                                                                           |

The log goes to standard error. Set `RUST_LOG=debug` for more detail.

## Limits

- Run the GC in one process per remote: set `gc.enabled = true` on that proxy only. Windsock does
  not enforce this rule. No lock stops a second GC runner. The GC protocol is model-checked with
  one GC runner and two writers only, so two GC runners on one remote are not verified. A proxy
  with `gc.enabled` logs `WARN another node ran the GC in the last horizon` at start and at each
  GC run when it reads a condemn of another node from the last horizon. The check can miss a
  second runner: it does not see a condemn that a prune redacted, or that a snapshot covers, as a
  new proxy loads the snapshot and does not read the entries under it.

- All remote data is encrypted with `repo.key`: see `docs/encryption.md`. Without this file,
  nobody can read the data.
- The remote store must keep the storage contract in `docs/storage.md`. Backblaze B2 and
  Garage do not. Run `windsockd diagnose <config>` before you use a new store.
- An `https` S3 remote needs the feature `tls`: `cargo build --release -p windsockd --features tls`.
  This feature compiles C (the `ring` crypto provider). The default build has no TLS and refuses an
  `https` endpoint. `ca_file` adds a PEM file of CA certificates to the public roots.
- Keys come from the configuration file. There are no per-bucket permissions.
- The ETag is the blake3 hash of the data, not an MD5. Tools that compare the ETag with a local
  MD5, such as `rclone --checksum`, see a difference.
- A PUT and a CompleteMultipartUpload take `If-None-Match: *` and `If-Match` (a list of ETags, or
  `*`). A mismatch gets 412 `PreconditionFailed`. `If-Match` on a missing key gets 404 `NoSuchKey`.
  The check and the write are one step on one proxy. Across proxies there is no check: two
  proxies can pass the check on the same ETag, and the index keeps one write by LWW and marks the
  key as a conflict. A proxy behind can see an older version: on a mismatch it syncs once and
  checks again (at most one such sync per second, shared by all requests), so it answers 412 only for a version that it cannot see. A pass on an old version
  stays possible across proxies. The check costs one manifest read when the manifest is not in
  the index, done outside the buffer lock.
- Presigned URLs, object tags, bucket lifecycle rules and ACLs are not supported.
- A multipart upload must complete on the proxy that started it.
- A GET streams the object in pieces of at most 4 MiB. One GET holds at most about 16 MiB: the
  stored bytes, the raw chunks and the piece. The peak for GETs is `max_connections` times 16 MiB.
  A failure in the middle of a GET cuts the response: the client never gets a short body with a
  clean end. A GET of an object that a client deletes or overwrites keeps working until the GC
  deletes its packs, at least R + H after the delete (48 h by default). A GET that runs longer is
  cut.
- Measured on macOS, one daemon, a 1 GiB object, readers at 200 KiB/s: an idle daemon holds
  17 MiB; 64 readers peak at 664 MiB, 250 readers at 1.6 GiB, and 288 connected readers at
  2.2 GiB, so 5 to 10 MiB per reader. After the readers stop, the allocator keeps about 1.3 GiB,
  and three more runs of 250 readers do not raise it.
- A client that stops reading a GET body holds its stream until `idle_timeout_secs` (60 s by
  default) after the last write that made progress. Then the daemon closes the connection. A client
  that reads slowly keeps it open: there is no minimum rate.
- A PUT, a CopyObject and a CompleteMultipartUpload hold the whole object in memory, up to 5 GiB
  per request. No limit covers all requests together: 10 parallel PUTs of 5 GiB need 50 GiB of
  memory. One PUT takes about 3 times its object: a PUT of 1 GiB raised the daemon to 3.1 GiB, so a PUT at the 5 GiB cap takes about 15 GiB. Size the memory for the largest objects times the parallel uploads, or put a limit in
  front of the proxy.

## Scale

Measured with 200,000 small objects in one bucket:

- The index takes about 510 bytes of memory (RSS) per key.
- A snapshot takes about 231 bytes per key. The GC writes it in parts of at most 1 GiB. A new
  proxy loads at most 16 GiB: about 74,000,000 keys. Above that, a new proxy replays the journal,
  or fails with an error that names the snapshot and the cap. `docs/storage.md` gives the format.
- A ListObjects page costs the same for any number of keys in the bucket: 1000 keys in about
  20 ms.

## Development

See `CLAUDE.md` for the code rules. `docs/storage.md` and `docs/encryption.md` give the design.

```bash
just check              # cargo fmt --check, clippy (default, tls, fuzz/)
just test               # cargo test --no-fail-fast
just fuzz 60            # each fuzz target for 60 s (nightly, cargo-fuzz)
just fuzz 600 pack_parse
just bench              # release build, writes bench.md
```

A workspace `cargo test` builds every crate with the feature `sim` of the engine tests, which
gives the journal a manual clock. To test the daemon as it ships, with no `sim`, run
`cargo test -p windsockd`.

The chaos soak runs 3 daemons on one directory remote under mixed S3 traffic, with kills,
restarts, a full disk under the buffer and the index, and a stop longer than H. At the end, every
proxy must read the same value for each key, and one that the acks allow. It needs macOS
(`hdiutil`), `rsync` and `lsof`, and exits 1 when a check fails:

```bash
cargo build --release -p windsockd -p chaos
./target/release/windsock-chaos --minutes 30 --work /tmp/ws-chaos --seed 13
```
