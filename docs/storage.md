# Storage contract

Windsock keeps the only durable copy of the data in the remote. The remote is a local
directory or an S3 bucket. Windsock is correct only on a store that keeps the contract below.

## What the store must provide

Windsock needs five properties from the store:

- A conditional create. A PUT with `If-None-Match: *` must fail with 412 when the object
  exists.
- Read-after-write consistency. A read after a successful write must return that write.
- List-after-write consistency. A list after a successful write must show the written object.
- Ranged reads. A read with a `Range` header must return that range and the bytes of that range.
- A delete. Only the GC and the storage probe use it.

The journal writes each entry with a conditional create at `log/<node_id>/<seq>`. Thus two
processes cannot write one entry. On a store that overwrites, two processes with one node
identity can write one seq, and the journal can lose an acknowledged write.

Windsock does not use a conditional overwrite (`If-Match`). Thus a store does not need it.

## Stores

| Store                            | Result                                                                     | Source                       |
| -------------------------------- | -------------------------------------------------------------------------- | ---------------------------- |
| Local directory (`DirRemote`)    | Keeps the contract                                                         | Windsock tests               |
| Windsock S3 server (`windsockd`) | Keeps the contract                                                         | Windsock tests               |
| SeaweedFS 4.48                   | Keeps the contract                                                         | Windsock test on 2026-10-07  |
| Garage 2.4.1                     | Does not keep it: it ignores `If-None-Match: *` and overwrites             | Windsock test on 2026-10-07  |
| Cloudflare R2                    | Keeps the contract. See [Cloudflare R2](#cloudflare-r2)                    | Windsock test on 2026-10-26  |
| Amazon S3                        | Not tested by Windsock. Its documentation describes `If-None-Match` on PUT | Provider documentation       |
| Backblaze B2                     | Not tested. Its S3 API does not document `If-None-Match` on PUT            | Provider documentation       |
| MinIO community edition          | Not tested. The project is archived, and its downloads answer 410 Gone     | Windsock check on 2026-10-07 |

Windsock speaks the S3 dialect only.

A store can accept a header and ignore it. Run the storage test before you use a new store.

## The storage test

The command `windsockd diagnose <config>` checks the remote of a configuration once:

```
ok storage contract (create, reject-create, read-after-write, list-after-write, ranged read)
```

The test does these steps on new objects:

1. It creates an absent object. The create must succeed.
2. It creates the same object again. The store must refuse the create.
3. It reads the object. The read must return the first write.
4. It lists the object. The list must show it.
5. It writes a second object and reads 5 bytes of it. The read must return those bytes.

A wrong answer is a violation, and the command exits with an error that names the store and
the step. An answer of 405 or 501 to a create or a ranged read is a violation too.

Each node also runs this test before it serves:

- A violation stops the node.
- Another error, such as a network fault or a refused credential, is ambiguous. The node runs
  the complete test again with new objects, 3 times at most.
- After 3 ambiguous errors, the node starts with a warning, because an outage can end after the
  start.

## Probe objects

The test writes and deletes small objects under `probe/`. If a delete fails, one small object
stays under `probe/`. Windsock never reads it. Do not put other data under `probe/` in the
key prefix of a Windsock remote.

Windsock also reserves `repo/`: it holds `repo/key-check`, see `encryption.md`.

## The S3 client

- At most 64 calls to the remote run at one time. The client keeps at most 64 idle connections.
  More calls wait for a slot.
- A call has at most 6 attempts. The pause between attempts starts at 100 ms and doubles up to
  5 s. One attempt stops after 60 s, and all attempts of one call stop after 120 s.
- Statuses 408, 429, 500, 502, 503 and 504 cause a new attempt, and so does a lost connection.
  Other statuses, such as 403 `RequestTimeTooSkewed`, fail at once with their S3 code in the log.
- The client does not follow a redirect.
- The client always verifies the TLS certificate and its host name. No setting turns the check
  off. For a private CA, set `ca_file`.
- An empty access key or secret key stops the start.
- A wait for a slot does not count in the time of an attempt, but it ends at the time limit of
  the call (120 s). A call frees its slot during the pause between attempts.

## Order of writes

- The versions of one key rank by the HLC of their ack, then by node ID. Every proxy gives the
  same order, also when an earlier write reaches the journal after a later one.
- That order is the real-time order of two writes only outside a window. A client writes a key
  through proxy A, gets the ack, then writes it through proxy B. The second write wins when the
  time between the two requests is more than the amount by which the clock of A is ahead of the
  clock of B. It also wins when B synced the entry of the first write before the second ack
  (flush delay plus sync interval, 1 s + 10 s by default). Inside that window, the first write
  can win. Through one proxy, the later ack always wins.
- The ack HLC is max(wall clock, last HLC that the proxy issued or saw) + 1. It never goes down
  on one proxy, also across a restart: at open, the clock passes the last HLC of every chain
  and the latest buffered ack.
- No HLC moves the clock of a proxy more than R past its wall clock. A reader treats an entry
  with an HLC more than R ahead of its own clock as a broken chain (`FutureHlc`). It logs one
  `ERROR entry HLC more than R ahead of this clock` with the node and the seq, the GC refuses to
  run, and the chain reads again once the clock of the reader passes that HLC less R. To find
  the node with a bad clock, read the node in that ERROR, then check the clock of the host that
  runs that node key.
- An entry HLC is at or above every ack HLC in the entry. A reader refuses an entry that breaks
  this rule, and names the node and the seq.
- Last-Modified is the ack HLC. It does not change at the flush.
- Format markers: `repo/key-check` holds the remote format, `data/engine/buffer/format` the
  buffer format, the local index a format key, and each snapshot a format byte. This build
  writes and reads format 2 only. An older format stops the open with an error that names both
  formats.

H, R and M are rules of the remote. The first proxy that opens a remote writes them into
`repo/key-check` (create-only), with the format. A proxy with other values refuses to open, and
the error gives the values of the remote and of the proxy. Known limit: H, R and M are fixed for
the life of a remote. To change them, start a new remote and copy the objects through the S3 API.

Late writes. A buffered write can reach the journal long after its ack, for example after a
restart or a long remote outage. A prune can then have removed a newer delete of its key, and a
commit would bring the key back. The rule: a proxy never commits a write whose ack HLC is older
than the late limit, R - M at the commit: R is `gc.retention_secs` (24 h by default), M is
`gc.late_margin_secs` (1 h), the clock skew that the rule allows. The check uses the HLC of the
entry that the proxy commits, also when it commits an intent after a restart.

- At a flush, such a write stops the flush before any plan or upload. The proxy logs
  `ERROR buffered writes older than the late limit` with the keys, refuses writes, and stops its
  flusher until a restart.
- At open, the proxy moves only the late writes to `data/engine/quarantine/<segment>.log` (or `<segment>.<n>.log`: a quarantine file is never replaced), and
  the open fails with the keys. The young writes stay in the buffer. The move survives a crash
  at each step: a record is in the buffer, in the quarantine, or in both, and the next open ends
  the move. A record in the quarantine never applies.
- While the quarantine holds files, the proxy does not start, and a start moves nothing more
  there.

What the operator does:

1. Read the keys in the ERROR line, or in the error of the failed start.
2. For each key, decide. To drop the late write, do nothing more for that key: the delete or the
   newer write that the remote holds stays. To keep the late write, read the record with the
   build that wrote it, and write the object again through the S3 API after the start. That new
   write gets a new ack HLC, so it wins over the delete.
3. Empty `data/engine/quarantine` (move its files away), then start the proxy. The young writes
   in the buffer flush at this start. Emptying the quarantine drops every late write in it that
   step 2 did not write again.

## Journal reads

Each sync lists the node markers once, then reads each chain from the seq after the last one it
read.

| When                        | For each chain                                             | Once          |
| --------------------------- | ---------------------------------------------------------- | ------------- |
| Each sync, no new entry     | 2 GET (the next seq, and the seq after it)                 | 1 LIST nodes/ |
| Each sync, k new entries    | k + 2 GET                                                  | 1 LIST nodes/ |
| First sync, and each GC run | also 1 LIST `log/<node>/` and 1 GET of the last entry read |               |

With the default sync interval (10 s), an idle chain costs 720 GET in one hour, and the node
markers cost 360 LIST. The GC run (1 h by default) adds 1 LIST and 1 GET for each chain.

A chain is broken, and the GC refuses to run, when:

- an entry does not verify: signature, hash, node, seq, link, or actions;
- seq n is missing and seq n + 1 exists (each sync);
- the listing holds a seq at or above the next seq after the read (first sync and each GC run):
  a gap of any length;
- the last entry read differs from the copy read before, or is gone (first sync and each GC run).

The sync report and the log give the node, the seq and the cause. A node with no marker is found
through the `seen` links of other entries.

Each open runs one full sync, with the audit, before it serves. The index is a cache: lost,
behind after a power loss, or a restored copy, it can miss the newest own entries, and the clock
must pass them before the first ack. When the own chain does not read at open, the start fails
with `ERROR the own chain does not read: no start` and the cause, for example `entry 7 is missing
and entry 999999999 exists (key log/<node>/00000000000999999999)`. An object that a writer with
no repo key put under the own chain gives this error. To act: read the ERROR, check the named key
in the bucket, remove it when it is not an entry of this proxy, and start again. The remote must
be reachable at start: a start with the remote down fails.

Known limit: a remote that drops the newest entries of a chain (a cut tail) looks like a chain
with fewer entries. No reader can tell. The next commit of the writer goes after the cut, so the
cut becomes a gap that the readers find at the first sync after open or at the next GC run. A
writer that never commits again leaves the cut unseen. To check by hand, compare the highest seq
under `log/<node>/` with the last `flushed seq=` line of that writer (log level debug).

## Open files

A daemon keeps these descriptors open. Each count has a cap.

| Kind                  | Cap                                      | Source                    |
| --------------------- | ---------------------------------------- | ------------------------- |
| Local index tables    | 128                                      | `index::MAX_OPEN_FILES`   |
| Remote connections    | 64 in use, 64 idle                       | `s3remote::MAX_IN_FLIGHT` |
| Buffer                | the active segment, the intent, the lock | 2 to 3 in the soak        |
| Chunk cache           | one file for each read in progress       | 0 to 1 in the soak        |
| S3 client connections | `max_connections`                        | soft fd limit - 256       |

The daemon keeps 256 descriptors out of the S3 connection limit for the first four kinds. In a
chaos soak on macOS, the index tables grew from 2 to 22 in 7 minutes.

## One GC runner

One process per remote runs the GC (`gc.enabled = true`). No lock enforces this, and the model
check covers one runner. A proxy with `gc.enabled` logs `WARN another node ran the GC in the last
horizon` when it reads a condemn entry of another node from the last horizon (24 h). The check
sees only condemn entries that no prune has redacted yet: a second runner can stay unseen.

## Snapshots

One PUT holds at most 5 GiB on S3, R2 and B2. The GC writes a snapshot in parts.

| Limit                   | Value                                        |
| ----------------------- | -------------------------------------------- |
| Size of one part        | 1 GiB at most                                |
| Parts in one snapshot   | 4096 at most                                 |
| Size of one snapshot    | 16 GiB at most: about 74,000,000 keys        |
| Ranged read of a part   | 64 MiB                                       |
| Parts with no head stay | for the GC horizon (`gc.horizon_secs`, 24 h) |

The format:

- The GC seals the snapshot as one blob, then cuts the blob into parts. Part n is
  `snapshots/<time>-<h>/<n, 6 digits>`. `h` is the blake3 hash of the sealed blob.
- The head `snapshots/<time>-<h>/head` holds the size and the blake3 hash of each part, and the
  frontiers of the snapshot. It is sealed with the key name as context. The GC writes it after
  all the parts.
- A snapshot in one object, `snapshots/<time>-<h>`, still loads.

The load:

- A load reads the head, then the parts. It checks the number of parts in the remote, and the
  size and hash of each part, before it uses the part. Then it checks the blob hash against the
  key, and opens the blob.
- A snapshot that does not load is skipped, and the next older snapshot loads. If none loads,
  the proxy replays the journal.
- The journal prune loads the newest snapshot in full first: every part, every hash, the open
  and the decode. It prunes under the newest snapshot that loads, never under one that does not
  load.

The GC:

- The GC deletes a snapshot when it is older than the snapshot that the same run loaded in full,
  and a newer snapshot is older than the GC horizon. It deletes the head first, then the parts.
- Parts with no head come from a write that stopped before its head, or from a delete that
  stopped after it. A load ignores them. The GC deletes them when its node has listed them for the GC
  horizon. The rule uses only the clock of the GC node, not the time in the key. The node keeps
  the first-listing times in `data/engine/snapshot-orphans`, so a restart keeps the count. Each writer leaves at most one such snapshot in one horizon.
- After it writes the head, the GC lists the parts again. When a part is gone, the snapshot
  write fails, and the previous snapshot stays in use.
- A snapshot key with a time ahead of the GC clock does not stop the GC from writing a new
  snapshot.

A failed load in the log:

- `WARN skipped a snapshot key=snapshots/.../head cause="..."`, once for each skipped snapshot.
  Causes: `the head is gone`, `the head does not open`, `the head lists N parts, over the cap of
4096`, `the head lists N parts, the remote has M`, `<part key> is gone`, `<part key> has N
bytes, the head says M`, `<part key> does not match its hash in the head`, `... bytes that do
not match the key hash`, `it does not open`, `it does not decode`.
- `WARN no snapshot loaded at open`: a new proxy found no snapshot that loads, and replays the
  journal.
- After a prune, the sync fails with `corrupt data: redacted entries and no snapshot loads:
<key>: <cause>; ...`, or `... and no snapshot in the remote`. The proxy cannot read the pruned
  writes until a snapshot loads. Restore the named object, or let the GC write a new snapshot
  from a proxy that has the full index.
- A snapshot over the cap is skipped with the cause `it is larger than 17179869184 bytes`
  or `the parts are over the cap of 17179869184 bytes`.
- The GC writes no snapshot above 16 GiB or 4096 parts. It logs `ERROR no new snapshot: no proxy
could load it`, keeps the previous snapshot, and goes on.

## Cloudflare R2

Test on 2026-10-26 with a release build, feature `tls`, from a Mac on a home link.

- R2 refuses a PUT with no `Content-Length` with 411 `MissingContentLength`. The node marker
  `nodes/<id>` is an empty object, and hyper sends no length for an empty body. Windsock sets
  `Content-Length` on every request.
- The storage test passes. A proxy with no state reads back every object that another proxy
  wrote, with multipart objects and ranged reads.

Latency, 64 KiB objects, 10 samples:

| Step                                          | p50    | Min    | Max      |
| --------------------------------------------- | ------ | ------ | -------- |
| PUT acknowledged until its log entry is in R2 | 704 ms | 439 ms | 2 962 ms |
| GET of a chunk not in the cache               | 150 ms | 129 ms | 266 ms   |
| GET of a chunk in the cache                   | 3 ms   | 2 ms   | 3 ms     |

Shutdown, 20 objects of 1 MiB:

- SIGTERM right after the puts: the drain takes 3.9 s. During the drain, a PUT gets 503 with
  `Retry-After: 5`, and a GET gets 200. A proxy with no state then reads the 20 objects.
- A second SIGTERM 0.5 s after the first stops the daemon with 20 MiB in the buffer. The next
  start replays and uploads them. A proxy with no state then reads the 20 objects.

## Versioned buckets

A versioned bucket keeps a hidden version of each overwritten or deleted object. Then the GC
and the journal redaction free no space. On such a bucket, set a lifecycle rule that expires
noncurrent versions.
