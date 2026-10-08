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

| Store | Result | Source |
|---|---|---|
| Local directory (`DirRemote`) | Keeps the contract | Windsock tests |
| Windsock S3 server (`windsockd`) | Keeps the contract | Windsock tests |
| SeaweedFS 4.48 | Keeps the contract | Windsock test on 2026-10-07 |
| Garage 2.4.1 | Does not keep it: it ignores `If-None-Match: *` and overwrites | Windsock test on 2026-10-07 |
| Amazon S3, Cloudflare R2 | Not tested by Windsock. Their documentation describes `If-None-Match` on PUT | Provider documentation |
| Backblaze B2 | Not tested. Its S3 API does not document `If-None-Match` on PUT | Provider documentation |
| MinIO community edition | Not tested. The project is archived, and its downloads answer 410 Gone | Windsock check on 2026-10-07 |

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

## Versioned buckets

A versioned bucket keeps a hidden version of each overwritten or deleted object. Then the GC
and the journal redaction free no space. On such a bucket, set a lifecycle rule that expires
noncurrent versions.
