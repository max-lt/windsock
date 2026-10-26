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

If the chunk cache disk is full or cannot be written, the proxy logs `cache writes fail, reads go to
the remote` once, and `cache writes work again` when a write works. Reads go on from the remote.

## Configuration

`windsockd init` writes all the settings with their default values. Relative paths are relative to
the configuration file.

| Setting                     | Default                                    | Meaning                                                                                                                                       |
| --------------------------- | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `data_dir`                  | `data`                                     | Engine state, write buffer, chunk cache, multipart parts, node key                                                                            |
| `repo_key`                  | `repo.key`                                 | The secret of the remote: it keys the chunk IDs and encrypts all remote objects. Every proxy of one remote needs the same file                |
| `listen`                    | `127.0.0.1:9000`                           | S3 address                                                                                                                                    |
| `max_connections`           | soft fd limit - 256 (half of it under 512) | Open S3 connections at most. Above it, new clients wait in the kernel backlog. The engine keeps the other descriptors                         |
| `idle_timeout_secs`         | `60`                                       | A connection with no request in progress closes after this time                                                                               |
| `request_timeout_secs`      | `300`                                      | A body upload that receives no byte for this time is cut. Each byte received starts the time again                                            |
| `remote.type`               | `dir`                                      | `dir` (with `path`) or `s3` (with `endpoint`, `bucket`, `prefix`, `region`, `access_key`, `secret_key`, and `ca_file` for a private CA)       |
| `[[keys]]`                  | one new pair                               | Key pairs that S3 clients sign with. Every key reaches every bucket                                                                           |
| `sync_interval_secs`        | `10`                                       | How often the proxy reads the writes of other proxies                                                                                         |
| `engine.cache_bytes`        | 16 GiB                                     | Chunk cache size. `0` turns the cache off                                                                                                     |
| `engine.flush_delay_ms`     | `1000`                                     | Longest time a write waits in the buffer before it goes to the remote                                                                         |
| `engine.buffer_limit_bytes` | 8 GiB                                      | Writes fail with `503 SlowDown` above this                                                                                                    |
| `gc.enabled`                | `false`                                    | Set to `true` on one proxy per remote. Windsock does not enforce this: see Limits                                                             |
| `gc.interval_secs`          | `3600`                                     | How often the GC runs                                                                                                                         |
| `gc.horizon_secs`           | `86400`                                    | GC horizon. Use the same value on every proxy of a remote. Keep it far above the time of one flush: under one hour, the daemon logs a warning |
| `gc.retention_secs`         | `86400`                                    | Old versions stay readable for this time                                                                                                      |

The log goes to standard error. Set `RUST_LOG=debug` for more detail.

## Limits

- Run the GC on one proxy per remote: set `gc.enabled = true` on that proxy only. Windsock does
  not enforce this rule. No lock stops a second GC runner. The GC protocol is model-checked with
  one GC runner and two writers only, so two GC runners on one remote are not verified.

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
- Presigned URLs, object tags, bucket lifecycle rules and ACLs are not supported.
- A multipart upload must complete on the proxy that started it.

## Development

See `CLAUDE.md` for the build, test and code rules, and `../windsock-todo.md` for the design.
