# Encryption

Windsock encrypts all data that it writes to the remote. A reader of the remote, such as the
cloud provider or the operator of a backup, cannot read the data. That reader also cannot test
whether a known file is stored.

## The repository key

One secret, `repo.key`, belongs to one remote. All proxies of that remote use the same file.

- `windsockd init` writes `repo.key` (64 hex characters, mode 0600) next to the configuration.
- The configuration key `repo_key` gives the path of the file.
- `windsockd run` stops when the file is missing. It never makes a new key, because a new key
  cannot read the data.
- To add a proxy to a remote, copy `repo.key` from a proxy of that remote.

If you lose `repo.key`, nobody can read the data on the remote. Keep a copy of the file in a safe
place, away from the remote and away from its backups.

Each proxy also has its own signing key, `node.key`. The signing key proves which proxy wrote a
journal entry. It does not give access to the data.

Each journal entry also carries a MAC under a subkey of `repo.key`, over the same fields as the
signature. A writer that can put objects in the bucket but has no `repo.key` can make a node key,
but not a valid entry: a reader checks the MAC before it uses the entry, so that chain is broken
and named, the other chains read, and the clock of the reader does not move. A redaction by the
GC keeps the MAC, because the MAC does not cover the sealed actions.

## For the operator

- `windsockd init <dir>` writes `<dir>/repo.key`: 64 hex characters, mode 600.
- `windsockd run` refuses `repo.key` and `node.key` when other users can read them. Run
  `chmod 600` on the file.
- Make a copy of `repo.key` at once. Keep the copy away from the remote and away from its backups.
  If you lose the key, you lose the data: no tool can read the remote without it.
- A cluster has one `repo.key`. To add a daemon, copy `repo.key` from a daemon of the cluster into
  the directory of the new daemon, then set mode 600. Each daemon makes its own `node.key`. Do not
  copy `node.key`.
- A daemon with another key does not start. The error is
  `repo.key is not the key of this remote`. Copy the key of the cluster.
- Windsock cannot change the key of a remote. Key rotation does not exist.
- The error `the remote has a journal and no repo/key-check: it was written without encryption`
  means that a build before the encryption wrote this remote. This build cannot read it. Use a new
  remote, or read the data with the old build and write it again through this build.

## What the key does

blake3 `derive_key` makes two subkeys from `repo.key`:

- The chunk ID key. A chunk ID is a keyed blake3 hash of the chunk. The same subkey gives the
  FastCDC seed, so the chunk sizes do not show the structure of an object. Dedup works across all
  buckets, because all proxies have the same key.
- The seal key. It encrypts with XChaCha20-Poly1305, with a random 24-byte nonce for each object.
  The associated data is the kind of object and its identity, so the bytes of one object do not
  open as another object.

A sealed object is `version | key ID (4 bytes) | nonce | ciphertext | tag`. It is 45 bytes
longer than its content.

## What the remote holds

| Object                      | Sealed                                                    | In clear                                                          |
| --------------------------- | --------------------------------------------------------- | ----------------------------------------------------------------- |
| `packs/<id>`                | Each chunk, and the footer with the chunk IDs and offsets | The header (format and nonce), the total size and the footer size |
| `manifests/<id>`            | All the content                                           | The key name                                                      |
| `log/<node>/<seq>`          | The actions: bucket names, object keys, inline manifests  | node, seq, prev, hlc, seen, and the signature                     |
| `snapshots/<time>-<h>/<n>`  | Part n of the sealed snapshot                             | The write time in the key name, the part number and size          |
| `snapshots/<time>-<h>/head` | The size and hash of each part, the frontiers             | The write time in the key name                                    |
| `snapshots/<time>-<h>`      | All the content (one object, read only)                   | The write time in the key name                                    |
| `repo/key-check`            | A known value                                             | Nothing else                                                      |
| `nodes/<node>`              | Empty marker                                              | The node ID                                                       |

A pack upload whose answer is lost is sent again with a new nonce. The first pack then has no
manifest, and the GC condemns it.

No read and no GC path reads the pack footer. The integrity of a pack rests on the seal of each
chunk.

A reader of the remote can see the number and the size of the objects, the time of each
journal entry, and which proxy wrote it.

## Wrong key

At start, the engine opens `repo/key-check`. If the remote has none, the first proxy writes it
with a create-only write. A proxy whose key does not open it does not start. Thus one remote
holds data under one key only.

## What you cannot change

- The chunk ID key cannot change. All chunk IDs depend on it, and a read checks each chunk
  against its ID.
- The seal key can change for new data later: each sealed object names its key with the key
  ID. Windsock does not rotate keys yet.

## The local disk

The write buffer, the chunk cache, the index and the intent file stay in clear on the local
disk of the proxy. Protect that disk with the operating system, for example with full-disk
encryption.
