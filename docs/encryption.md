# Encryption

Windsock encrypts the data that it writes to the remote. The cloud provider and the backup
operator of the remote cannot read the data, the object keys or the metadata.

## Threat model

Windsock protects the data from:

- The operator of the remote store, for example the cloud provider.
- The operator of a copy of the remote, for example an S3 Glacier backup.

Windsock does not protect the data from a person who can read the disk of a proxy. The chunk
cache, the write buffer, the index, the multipart parts and the configuration stay in clear on
that disk. The repository key is in a file on that disk too.

## The repository key

One remote has one repository key: 32 random bytes. `windsockd init` writes it to `repo.key`,
next to the configuration, readable by its owner only. The setting `key_file` names the file.

- Every proxy of one remote must use the same key file. Copy it to each proxy.
- Keep a copy of the key file offline. If you lose the key, you lose all the data in the remote.
- The key does not rotate. A new key needs a new remote.

Windsock derives three values from the repository key with `blake3::derive_key`:

| Value    | Use                                                                   |
| -------- | --------------------------------------------------------------------- |
| Hash key | Keyed blake3 for the chunk IDs and for the signed hash of the actions |
| Seal key | XChaCha20-Poly1305 for the sealed objects                             |
| Key ID   | Public name of the key, in the remote object `key-id`                 |

## The key check

The remote object `key-id` holds the key ID of the repository key. The first proxy writes it
with a conditional create. Each proxy reads it before it serves. A proxy with another key
refuses to start: it would write chunks that the other proxies cannot read or dedup.

## Chunk IDs

A chunk ID is the blake3 hash of the raw chunk, keyed with the hash key. Without the key, a
reader of the remote cannot test whether a known file is stored. Dedup stays global: two
buckets that store the same chunk store it once.

## Sealed objects

A sealed object is `nonce (24 bytes) | ciphertext | tag (16 bytes)`. The seal adds 40 bytes.

| Object          | Sealed part                          | Nonce                               |
| --------------- | ------------------------------------ | ----------------------------------- |
| Chunk in a pack | Each stored chunk, after compression | Pack nonce, then the chunk position |
| Pack footer     | The list of chunks                   | Pack nonce, then `u64::MAX`         |
| Manifest        | All of it, after the version byte    | Manifest nonce, then zero           |
| Journal entry   | The actions                          | Random                              |
| Snapshot        | All of it, after the version byte    | Random                              |

Each chunk has its own seal, so a ranged read still reads one chunk. The pack nonce and the
manifest nonce come from 32 random bytes for each flush. Thus a nonce never repeats under one
key.

A journal entry signs the keyed hash of its actions, not the sealed actions. The prune can drop
the sealed actions and keep the chain valid. A reader opens the actions, then compares their
keyed hash with the signed hash: an entry cannot take the actions of another entry.

The seal also authenticates. Only a holder of the key can write a snapshot or a manifest that a
proxy accepts.

## What the remote shows

The encryption does not hide:

- The number, the sizes and the write times of packs, manifests, snapshots and journal entries.
- The size of each stored chunk, from the ranged reads of a proxy.
- The node IDs, the seq, the HLC and the `seen` links of each journal entry.
- The access pattern: which objects a proxy reads, and when.
- The condemn and the delete of a pack or a manifest by the GC.

## Cost

Measured on 2026-10-08 with `scripts/bench.sh` on a shared cloud VM (4 vCPU, Xeon 2.1 GHz,
DirRemote), two runs before and two runs after the encryption:

- Writes: no change. A put is acknowledged from the local buffer, before the seal.
- Reads from the cache: no change. The cache holds raw chunks.
- Cold reads: about 0.8 ms more for each GET (p50 3.2 ms before, 4.0 ms after).
- One core seals 650 MB/s and opens 1.1 GB/s. Keyed blake3 runs at the speed of blake3.
- Storage: 40 bytes for each stored chunk.
