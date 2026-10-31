//! Copies of an object to another key. The data of the source goes through a spool file, as a
//! streamed put, and takes room in the read budget piece by piece, as a GET.

use super::*;

/// The largest write to the spool of a copy.
const COPY_PIECE: usize = 1024 * 1024;

impl<R: Remote + 'static> Engine<R> {
    /// Copies `source` (bucket, key) to `target`. `metadata` replaces the metadata of the source,
    /// and `None` keeps it. With no room in the read budget after `wait`, fails with ReadBudget.
    pub async fn copy(
        &self,
        source: (&str, &str),
        target: (&str, &str),
        metadata: Option<BTreeMap<String, String>>,
        mode: WriteMode,
        wait: Duration,
    ) -> Result<ObjectInfo> {
        let mut room = Some(self.read_room(Some(wait)).await?);
        // The reader fixes the source version now: a later delete or overwrite of the source does
        // not change what the copy reads.
        let mut reader = self.get_reader(source.0, source.1, None).await?;
        let metadata = metadata.unwrap_or_else(|| reader.info.metadata.clone());
        let mut spool = self
            .begin_put_sized(target.0, target.1, metadata, mode, reader.info.size)
            .await?;
        loop {
            let held = match room.take() {
                Some(room) => room,
                None => self.piece_room(&mut reader).await?,
            };
            let Some(piece) = self.next_piece(&mut reader).await? else {
                break;
            };
            for part in piece.chunks(COPY_PIECE) {
                self.spool_write(&mut spool, part).await?;
            }
            crate::sim::crash_point(crate::sim::Point::CopyPiece)?;
            drop(held);
        }
        if spool.content_hash() != reader.info.content_hash {
            return Err(EngineError::Corrupt(
                "the copied data does not match the hash of its source".to_string(),
            ));
        }
        self.finish_put(spool).await
    }
}
