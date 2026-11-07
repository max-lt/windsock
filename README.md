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

   `./target/release/windsockd --version` prints the package version and the commit of the
   build, for example `0.2.0+4d30d42`. A build from a source tree with no git checkout prints
   the package version only. The `listening` log line has the same value in its `version` field.

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

`data_dir` must persist across restarts: it holds the buffer of acked writes and `node.key`. A
restart with the same `data_dir` keeps its node identity and makes no new chain. A start with no
`node.key` makes a new identity, and its first write makes a new chain, which each entry lists until
the GC retires it (`gc.retire_chains`); on a remote that
has chains, that start logs `a new node identity on a remote with N chains`. A container with no
persistent volume for `data_dir` loses acked writes and adds one chain at each start.

A start that fails, for example on a quarantine or a remote with other rules, fails again at
each restart: read the error, act, then start again.

A start that fails with `the own chain is broken` gives a cause. Only a gap names a key: check
that key in the bucket, and remove it when this proxy did not write it. Do not remove an entry
for an HLC ahead of the clock: fix the clock. `docs/storage.md` (Open refusals) gives each
refusal, its cause and the action.

## Time rules

| Name | Setting               | Default | What it does                                                                                                                                      |
| ---- | --------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| H    | `gc.horizon_secs`     | 24 h    | The GC deletes a dead object H after its condemn                                                                                                  |
| R    | `gc.retention_secs`   | 24 h    | Old versions stay readable for R; the bound for an HLC ahead of a clock                                                                           |
| M    | `gc.late_margin_secs` | 1 h     | The clock skew that the late write rule allows                                                                                                    |
| Q    | max(R, H) + M         | 25 h    | With `gc.retire_chains`, a chain with no entry for Q can be retired. The quiet check relies on the clock skew bound M, as the other time rules do |

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

A PUT, copy or complete that streams its body commits it as a new segment. When that commit fails
after its segment is known to the buffer, for example on a full disk, the log names the cause once:
`a spooled commit failed`. From then on the buffer refuses writes, and the key of that write fails
to read, until a restart. The restart reads the buffer again and recovers: the failed write had no
ack, so it is not there, and the other writes are.

The buffer directory holds a file `format` with the record format (3). A buffer of another
format stops the start with both numbers: start the build that wrote it and let it flush. If the
file is empty or does not read, for example after a power loss, and this build wrote the buffer,
write `3` into it and start again.

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

## Change the cache size of a running proxy

```bash
windsockd cache-trim /etc/windsock/windsock.toml            # empty the chunk cache
windsockd cache-trim /etc/windsock/windsock.toml 2147483648 # keep at most 2 GiB
```

The command reaches the running daemon through `data/admin/admin.sock` and prints the new limit,
the bytes held and `cache_bytes`. The limit is at most `engine.cache_bytes`, because the start
checks the free disk for that value. A restart goes back to `cache_bytes`. The oldest chunks go
first. A read that has a chunk file open keeps its data. The next read of an evicted chunk goes to
the remote. The directory `data/admin` has mode 0700 and the socket 0600: only the user of the
daemon can use them. At start, the daemon refuses a `data/admin` that is a link, belongs to another
user or that other users can open, and replaces a socket that a stopped daemon left. A Unix socket
path takes at most 103 bytes: with a longer `data_dir/admin/admin.sock`, the daemon starts with
no admin socket and logs one WARN with the path, its length and the fix (a shorter `data_dir`).
`windsockd cache-trim` then fails with `no admin socket: data_dir is too long`, and the console
sees `admin_socket = false` in the node status.

## Configuration

`windsockd init` writes all the settings with their default values. Relative paths are relative to
the configuration file.

| Setting                     | Default                              | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| --------------------------- | ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `data_dir`                  | `data`                               | Engine state, write buffer, chunk cache, multipart parts, node key                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `repo_key`                  | `repo.key`                           | The secret of the remote: it keys the chunk IDs and encrypts all remote objects. Every proxy of one remote needs the same file                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `listen`                    | `127.0.0.1:9000`                     | S3 address                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `max_connections`           | min((soft fd limit - 256) / 2, 4096) | Open S3 connections at most. Above it, new clients wait in the kernel backlog. A connection can hold a socket and a file at once, and the engine keeps 256 descriptors. At start the daemon raises the soft limit to min(hard limit, 8192). It does not start under 512 descriptors, or with a value that needs more than 2 x max_connections + 256                                                                                                                                                                                                                                       |
| `idle_timeout_secs`         | `60`                                 | A connection with no request in progress closes after this time. At least 1                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `request_timeout_secs`      | `300`                                | A body upload that receives no byte for this time is cut. Each byte received starts the time again. At least 1                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `uploads_expire_secs`       | `604800` (7 days)                    | A multipart upload with no initiate and no part for this time is removed, with its parts. The check runs every hour. The minimum is 3600. The proxy must also have run for this time since it first saw the upload, so a wall clock step does not remove a fresh upload. A proxy that restarts more often than this never removes an upload: clients list them with ListMultipartUploads and remove them with AbortMultipartUpload                                                                                                                                                        |
| `remote.type`               | `dir`                                | `dir` (with `path`) or `s3` (with `endpoint`, `bucket`, `prefix`, `region`, `access_key`, `secret_key`, and `ca_file` for a private CA)                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `[[keys]]`                  | one new pair                         | Key pairs that S3 clients sign with. Every key has every grant on every bucket                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `sync_interval_secs`        | `10`                                 | How often the proxy reads the writes of other proxies. At least 1                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `engine.cache_bytes`        | 16 GiB                               | Chunk cache size. `0` turns the cache off                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `engine.flush_delay_ms`     | `1000`                               | Longest time a write waits in the buffer before it goes to the remote                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `engine.buffer_limit_bytes` | 8 GiB                                | Writes fail with `503 SlowDown` above this                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `engine.parts_limit_bytes`  | 10 GiB                               | The parts of all open multipart uploads together, on the disk of `data_dir`, outside the buffer limit. A part fails with `503 SlowDown` above this while other uploads hold the room, and plain writes go on. A part that cannot fit even with no other upload, with the other parts of its upload, gets `400 EntityTooLarge`. A part sent again counts with the part it replaces until it gets its name, so the default holds a 5 GiB object plus one 5 GiB part sent again. Clients free the room with ListMultipartUploads and AbortMultipartUpload, or the expiry removes the uploads |
| `engine.read_budget_bytes`  | 1 GiB                                | The pieces of GETs in flight on all connections together, 4 MiB each. A GET whose first piece finds no room in 5 s gets `503 SlowDown`. Later pieces wait. The minimum is 64 MiB and the maximum 1 TiB. The room counts pieces, not memory: a piece gives its room back when less than 408 KiB of it waits in the socket queue, so a reader can hold 2 pieces (8 MiB) against 4 MiB of room. Measured: 250 slow readers on the budget of 1 GiB peak at 1.6 GiB RSS                                                                                                                        |
| `engine.read_ahead`         | `3`                                  | Pieces that a GET of the remote reads ahead at most, `0` to `8`. `0` turns read-ahead off                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `engine.copy_ref_min`       | `0`                                  | A CopyObject of a source of at least this many bytes writes a new manifest of the stored chunks and moves no data. `0` turns it off. It stays off by default until the model check of the copy passes on a build machine                                                                                                                                                                                                                                                                                                                                                                  |
| `gc.enabled`                | `false`                              | Set to `true` on one proxy per remote. Windsock does not enforce this: see Limits                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `gc.interval_secs`          | `3600`                               | How often the GC runs. At least 1                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `gc.horizon_secs`           | `86400`                              | GC horizon. Use the same value on every proxy of a remote. Keep it far above the time of one flush: under one hour, the daemon logs a warning                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `gc.retention_secs`         | `86400`                              | Old versions stay readable for this time                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `gc.late_margin_secs`       | `3600`                               | Clock skew that the late write rule allows. A buffered write older than `retention_secs - late_margin_secs` at its commit goes to quarantine. Must be under `retention_secs`                                                                                                                                                                                                                                                                                                                                                                                                              |
| `gc.snapshot_interval_secs` | `86400`                              | The GC writes a snapshot when the latest one is this old                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `gc.retire_chains`          | `false`                              | The GC retires each chain with no entry for max(R, H) + M, in entries of at most 500 chains, so writers leave it out of their seen and the header stays small. Off until the model check of its rules passes at its final bounds                                                                                                                                                                                                                                                                                                                                                          |

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
- Keys come from the configuration file, and each one can do every operation on every bucket. A
  process that embeds windsockd gives the keys through a `KeyStore` (`windsockd::serve_with`), and
  the configuration then has no `[[keys]]` entry. The store gives the secret and the `Grants` of
  each key:
  - Access on a bucket is `Read` (GET, HEAD, listings) or `ReadWrite` (also the writes, deletes,
    multipart steps and DeleteBucket). The access of a key on a bucket is the greatest of
    `all_buckets`, its entry in `buckets`, and `ReadWrite` on a bucket that the key created when
    `create_bucket` is set.
  - CreateBucket needs `create_bucket`. A copy needs `Read` on its source bucket and `ReadWrite` on
    its destination. ListBuckets shows only the buckets that the key can reach.
  - A request on a bucket that the key cannot reach gets 403 `AccessDenied`, also when the bucket
    does not exist. A presigned URL takes the same check.

  The store is asked on every request, with no cache:
  a failed lookup, or one that takes more than 2 s (`KEY_STORE_DEADLINE`), gets
  `503 ServiceUnavailable`. When `serve_with` returns or its future is dropped, its tasks and its
  client connections stop, with the requests in progress, and each call of its `Node` gets
  `EngineError::Stopped`. The host drops the `Node`: it holds the engine, and a new serve of the
  same `data_dir` opens only once it is gone.

- `Node::metrics()` gives the counters of the S3 port since the start: open and accepted
  connections, the open connections of each client IP, the requests in progress, and one row of
  totals (count, body bytes in and out, duration) for each access key, bucket, operation and
  status. A request counts when its response body ends. A request that fails the signature check
  has no access key and no bucket. A request whose client goes away before the response gets the
  status 499. The table keeps at most 4096 rows. Past that, a new row goes to the row of bucket
  `<overflow>` for its operation and status. The counters are in memory: a restart sets them to
  zero.
- The ETag is the blake3 hash of the data, not an MD5. Tools that compare the ETag with a local
  MD5, such as `rclone --checksum`, see a difference.
- The proxy does not check the value of `Content-MD5` or of `x-amz-checksum-*`, in a header or in
  an aws-chunked trailer. It checks `x-amz-content-sha256` and the trailer signature.
- A PUT and a CompleteMultipartUpload take `If-None-Match: *` and `If-Match` (a list of ETags, or
  `*`). A mismatch gets 412 `PreconditionFailed`. `If-Match` on a missing key gets 404 `NoSuchKey`.
  The check and the write are one step on one proxy. Across proxies there is no check: two
  proxies can pass the check on the same ETag, and the index keeps one write by LWW and marks the
  key as a conflict. A proxy behind can see an older version: on a mismatch it syncs once and
  checks again (at most one such sync per second, shared by all requests), so it answers 412 only for a version that it cannot see. A pass on an old version
  stays possible across proxies. The check costs one manifest read when the manifest is not in
  the index, done outside the buffer lock.
- Object tags, bucket lifecycle rules and ACLs are not supported.
- This build writes buffer records of format 3. It refuses at start a buffer of format 2, from an
  earlier build. Start the earlier build, stop it with SIGTERM (it flushes the buffer, and exits 0
  when the buffer is empty), then start this build. There is no conversion.
- Presigned URLs (SigV4 in the query) cover GET, HEAD and a single PUT of an object. Multipart,
  copy, delete and bucket requests need a signed header. `X-Amz-Expires` is 1 to 604800 seconds
  (7 days). A URL is valid from `X-Amz-Date` less 15 minutes of clock skew, until `X-Amz-Date`
  plus `X-Amz-Expires`, with no skew at the end. While the clock of the proxy is more than R ahead
  of its wall clock, a presigned request gets `503 SlowDown`: the expiry needs a trusted wall
  clock. A step back of the wall clock under R can make an expired URL valid again for the length
  of the step.
- The holder of a presigned URL has the grants of the key that signed it, on every bucket that
  the key can reach, until the expiry. The holder chooses each header that the URL does not sign: Content-Type, user
  metadata, If-Match and If-None-Match. Sign Content-Type when it matters. A PUT URL works many
  times until its expiry, each time for an object up to the buffer limit. Each PUT over 1 MiB
  goes through a spool file (see below).
- A multipart upload must complete on the proxy that started it.
- A GET streams the object in pieces of at most 4 MiB. One GET holds at most about 16 MiB: the
  stored bytes, the raw chunks and the piece. The peak for GETs is `max_connections` times 16 MiB.
  A failure in the middle of a GET cuts the response: the client never gets a short body with a
  clean end. A GET of an object that a client deletes or overwrites keeps working until the GC
  deletes its packs, at least R + H after the delete (48 h by default). A GET that runs longer is
  cut.
- A GET of the remote reads up to `engine.read_ahead` pieces (default 3) ahead of the piece that
  it sends, each in its own task. The depth follows the client. The reader keeps the time that
  the client took to ask for each of its last two pieces (the gap; the first gap does not count)
  and the time of each of its last two fetches. With the larger of each, the depth is
  `ceil(fetch / gap)`, at least 1 and at most `engine.read_ahead`. A client whose gap is more than
  4 times the fetch gets no read-ahead. A client that slows down stops its surplus pieces at once
  and gives their room back. The first two pieces of a GET, and a piece that the cache holds,
  start no read-ahead. Read-ahead never waits: a piece ahead takes room in the read budget only
  while all the room in use, with it, stays within half of the budget, and a remote read only
  while fewer than 32 run for read-ahead. Otherwise the GET goes on one piece at a time. A client
  that goes away stops its read-ahead tasks. The pieces leave in order, and a failed fetch cuts the
  response when its piece is due. One GET holds at most 1 + `engine.read_ahead` pieces.
- A client that needs speed from the remote sends GETs of whole objects, or ranges of 32 MiB or
  more: a range of 8 MiB gets no read-ahead.
- Read-ahead measured in release on macOS, a remote with 200 ms per read, cache off, a 1 GiB
  object, `engine.read_ahead` 0 then 3. One GET: 61.1 s then 15.9 s, RSS growth 22 MiB then
  90 MiB. Four GETs of 256 MiB one after the other: 61.6 s then 17.4 s. Four clients that each
  read 8 MiB ranges in order: 86.3 s then 85.3 s, RSS growth 83 MiB then 58 MiB, because a range
  of two pieces starts no read-ahead. The same with 32 MiB ranges: 67.8 s then 29.6 s, RSS growth
  89 MiB then 253 MiB. On a 256 MiB read budget, 250 readers at 200 KiB/s get 178 to 181
  refusals (503) at depth 0 and 175 to 186 at depth 3: readers this slow start no read-ahead. 8
  fast readers and 242 readers at 200 KiB/s get 173 and 178 refusals at depth 0, 172 and 174 at
  depth 3.
- Measured on macOS, one daemon, a 1 GiB object, readers at 200 KiB/s: an idle daemon holds
  17 MiB; 64 readers peak at 664 MiB, 250 readers at 1.6 GiB, and 288 connected readers at
  2.2 GiB, so 5 to 10 MiB per reader. After the readers stop, the allocator keeps about 1.3 GiB,
  and three more runs of 250 readers do not raise it.
- With the read budget at 64 MiB, of 250 readers 16 get 200 and 234 get `503 SlowDown`, and the
  daemon peaks at 253 MiB. At the default budget of 1 GiB, 250 readers all get 200, at 1.6 GiB.
- A client that stops reading a GET body holds its stream until `idle_timeout_secs` (60 s by
  default) after the last write that made progress. Stalled readers can hold the whole read budget for that time: the 503 then protects the memory, not the service. Then the daemon closes the connection. A client
  that reads slowly keeps it open: there is no minimum rate.
- A PUT with a Content-Length over 1 MiB, or with no Content-Length (a chunked or HTTP/2 body),
  writes its body to a spool file in the buffer as it arrives, in pieces of at most 1 MiB: it
  holds about 1 MiB of memory, and the peak for such PUTs is `max_connections` times 1 MiB. Its
  spool file counts against the buffer limit as it grows. A PUT with a declared length takes the buffer room of
  that length at its start: with no room, it gets `503 SlowDown` before its body is read. A smaller PUT goes through the buffer
  in one record, with the group fsync.
- Every other request body is read whole into memory, up to a cap: 1 MiB for a PUT of an
  object, 4 MiB for an XML body (a POST or a bucket PUT), 64 KiB for any other request, a copy
  included. A Content-Length over the cap gets `400` before the body is read. The peak for these
  bodies is `max_connections` times 4 MiB. A request whose `x-amz-content-sha256` is not a SHA-256 hex digest,
  `UNSIGNED-PAYLOAD` or a known `STREAMING-` value, or that has a Content-Length and a
  Transfer-Encoding, gets `400` before its body is read. The signature check uses the headers and the declared payload hash
  only: a request with a bad signature gets `403` before any byte of its body is read. The hash of
  the body is checked after the read.
- An aws-chunked body is decoded as it arrives: a header or trailer
  line takes at most 4 KiB, all trailers 16 KiB, and a declared chunk size reserves no memory.
  Each chunk signature is checked at the end of its chunk, and nothing is written before the last
  chunk, the trailer signature and `x-amz-decoded-content-length` match.
- Measured on macOS, one daemon, PUTs of a 100 MiB file at 200 KiB/s for 60 s: 64 writers raised
  the daemon from 224 MiB to 241 MiB, and 250 writers from 43 MiB to 106 MiB, about 260 KiB per
  writer, with 2.9 GiB in spool files. When the clients stopped, no spool file stayed. The same
  measure with aws-chunked PUTs (`STREAMING-UNSIGNED-PAYLOAD-TRAILER`, chunks of 64 KiB): 64
  writers raised the daemon from 53 MiB to 60 MiB, and 250 writers from 60 MiB to 155 MiB, about
  390 KiB per writer, with 2.9 GiB in spool files and none after the stop.
- The flush and the replay at start read a buffered object in pieces of 1 MiB. The flush holds
  one pack target (`pack_target`, 64 MiB by default) and one piece, not the object. Measured on
  macOS, release build, one buffered object flushed at SIGTERM: 100 MiB peaked at 83 MiB, and
  1 GiB at 96 MiB; the replay at start of either peaked at 8 MiB.
- A CompleteMultipartUpload copies its parts to a spool file in pieces of at most 1 MiB, and
  takes the buffer room of the whole object first: with no room, it gets `503 SlowDown` with
  `Retry-After`, and the parts stay. At most `MAX_COMPLETES` (4) run at once; more get
  `503 SlowDown`. On disk, the parts and the spool exist together, so a complete needs up to 2
  times the object: 10 GiB for an object at the 5 GiB cap. Measured on macOS (NVMe, release
  build): a complete of 1 GiB took 1.1 s, of 5 GiB 4.8 s, and 4 completes of 1 GiB at once took
  1.2 s and raised the daemon by 0.8 MiB. The proxy sends nothing while a complete copies: a
  client whose read timeout is shorter than the copy sees a timeout. A slower disk makes the copy
  longer, about 50 s for 5 GiB at 100 MB/s.
- A crash during a complete: before its commit, the next start gives the upload back with its
  parts, and the complete can run again. After its commit, the next start removes the parts; the
  object is there, and a second complete of the upload gets `404 NoSuchUpload`. The start knows
  the commit by the hash of the object, which the complete writes in its upload before the
  commit. If the key was overwritten or deleted between that commit and the crash, the start gives
  the upload back, and a client that sends the complete again writes the object again. This needs
  a crash in that short window, and only that client is affected.
- An UploadPart writes its body to a temporary file in its upload directory as it arrives, in
  pieces of at most 1 MiB, with the body checks of a PUT. The room of the declared body in
  `parts_limit_bytes` is taken first; with no room it gets `503 SlowDown`, and a part that the limit
  cannot hold with the other parts of its upload gets `400 EntityTooLarge`. The part gets its name
  after a fsync, then the directory is fsynced: a part sent again replaces the old one, and the
  last of two parts of one number wins. A cut body or a failed check leaves no part, and a start
  removes the temporary files of a crash. Measured as for the PUT, with parts of 100 MiB at
  200 KiB/s: 250 writers raised the daemon from 40 MiB to 102 MiB, about 250 KiB per writer.
- A crash after a part got its name and before the removal of the part of the same number that it
  replaced leaves two parts of one number. The next start keeps the newest by modification time.
  If the clock stepped back between the two writes, it keeps the older one; the new part had no
  ack, so its client sends it again.
- A CopyObject reads its source as a GET does, one piece at a time with room in the read budget
  (the first piece waits 5 s, then `503 SlowDown`), and writes it to a spool file in pieces of at
  most 1 MiB. It takes the buffer room of the whole object first (`503 SlowDown` with no room).
  The reader fixes the source version at the start: a delete or an overwrite of the source during
  the copy does not change what it copies. A source that is still only in the buffer works.
  `If-Match`, `If-None-Match: *` and a create-only prefix apply to the destination, as for a PUT. A
  copy onto itself (metadata `REPLACE`) works. At most 16 copies run at once; more get `503 SlowDown` with
  `Retry-After`. A client that goes away drops the spool file. The
  read pieces are up to 4 MiB, as for a GET, and count in the read budget; the 1 MiB bound is for
  the write pieces. Measured on macOS, release build, a flushed source of 1 GiB: one copy took
  2.2 s, and 8 copies at once 3.9 s. With the cache off, one copy raised the RSS by 18 MiB.
- With `engine.copy_ref_min` above 0, a CopyObject of a source of at least that size goes by
  reference. The copy reads no data: it writes a new manifest of the chunks that the index of
  this proxy locates, and one journal entry, under GC rules 1 and 2 as a dedup. It costs 1
  manifest PUT (none for a manifest of 4 KiB or less, which goes in the entry) and 1 entry
  create. The ack waits for the entry in the remote and its apply in the index, not for a local
  fsync. It reads no pack, so it does not find a damaged pack of the source; a later read of the
  copy finds it, as a read of the source does. At most 4 copies by reference read their source
  manifest and write the new one at once. Each holds room in the read budget for its manifests
  in memory: the larger of 2 decoded manifests, or 1 decoded manifest and 2 times its encoding.
  The commit of the entry waits for a flush in progress, with no room and no slot held. Measured on macOS, release build, on a local
  remote with 30 ms per call, after the first write of the process: a copy by reference made 2
  remote calls and took 100 to 120 ms from 4 MiB to 256 MiB. A spool copy took 61 ms at 16 MiB
  and 539 ms at 256 MiB with the cache on, and 210 ms and 979 ms with the cache off, plus the
  flush. For 327,680 chunks (5 GiB in chunks of 16 KiB), the manifest has 23.7 MiB, and its
  decode, the index lookups and the new encoding took 245 ms. A copy goes through the spool in
  place of a reference when:
  - `engine.copy_ref_min` is 0, or the source is smaller;
  - the source is still only in the buffer of this proxy;
  - the destination has a buffered write on this proxy;
  - no complete sync is younger than H/2 (a broken chain);
  - the sync before the copy fails on the remote, or takes more than 10 s;
  - a chunk of the source has no location in the index (its pack is condemned);
  - the destination prefix has another chunking or compression than the source prefix.

  After the first remote write of a copy by reference, it never goes through the spool: the
  entry can be in the remote. A remote error then fails the copy, and the next flush applies an
  entry that landed. With a sync younger than H/2, the manifest PUT is the first remote call, so
  a remote that is down fails the copy. While a copy by reference runs, a conditional write to
  its destination on this proxy (`If-None-Match: *`, `If-Match`, a create-only prefix) gets
  `409 ConditionalRequestConflict`.

- An UploadPartCopy reads a range of its source as a GET does, with room in the read budget, and
  writes it as an upload part, with the checks and the room of an UploadPart. The range in
  `x-amz-copy-source-range` is `bytes=first-last`, with both bytes in the source; any other value
  gets `400 InvalidArgument`. With no range, the part is the whole source. The reader fixes the
  source version at the start. The part ETag is the blake3 hash of its data, as for an
  UploadPart. A condition on the source (`x-amz-copy-source-if-*`) gets `501 NotImplemented`, as
  for a CopyObject. Part copies count in the 16 copies that run at once. A client that goes away
  drops the part file.

## Scale

Measured with 200,000 small objects in one bucket:

- The index takes about 510 bytes of memory (RSS) per key.
- A sync holds a journal entry about 3 times in memory at its peak: the sealed bytes, the plain
  actions and the decoded actions. That is about 1.5 GiB for an entry at the writer bound of 512 MiB
  (`max_entry_actions`).
- A snapshot takes about 231 bytes per key. The GC writes it in parts of at most 1 GiB. A new
  proxy loads at most 16 GiB: about 74,000,000 keys. A load needs memory of 2 times the snapshot at its peak. Above that, a new proxy replays the journal,
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
restarts, a full disk under the buffer and the index, and a stop longer than H. The traffic holds
puts up to 24 MiB, multipart uploads with parts up to 6 MB, copies, and GETs of large objects that
read ahead, some by clients that go away at a random point. Other clients go away in the body of a PUT or of a
part, which the proxy must never take, or while the proxy runs a copy or a complete. At the end, every proxy must read the
same value for each key, and one that the acks allow. During the load, the body of each whole GET and the
ETag of each acked copy must be a value that the key or the copy source had. It needs macOS
(`hdiutil`), `rsync` and `lsof`, and exits 1 when a check fails:

```bash
cargo build --release -p windsockd -p chaos
./target/release/windsock-chaos --minutes 30 --work /tmp/ws-chaos --seed 13
```
