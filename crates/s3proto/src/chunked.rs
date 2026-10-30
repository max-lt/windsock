//! `aws-chunked` bodies, decoded as they arrive. Memory does not grow with the declared sizes:
//! a header line, the trailers and the hash of one chunk are bounded, and data goes out as slices
//! of the input.
//!
//! The data of a chunk goes out before its signature is checked at the end of the chunk. The
//! caller keeps the data aside and commits nothing before [`ChunkDecoder::finish`] succeeds.

use sha2::{Digest, Sha256};

use crate::sigv4::{ChunkSigner, same_signature};

/// The longest chunk header or trailer line, without its CRLF. A signed header is about 90 bytes.
pub const MAX_LINE: usize = 4096;
/// All trailer lines together.
pub const MAX_TRAILERS: usize = 16 * 1024;

/// An `aws-chunked` body that does not decode, or a chunk signature that does not match.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChunkError {
    #[error("malformed aws-chunked body")]
    Malformed,
    #[error("chunk signature does not match")]
    BadSignature,
    #[error("the aws-chunked body ends before its last chunk")]
    Incomplete,
}

#[derive(Clone, Debug)]
enum State {
    Header,
    Data {
        left: u64,
        signature: Option<String>,
    },
    /// The CRLF after the data of a chunk: how many of its two bytes came.
    DataEnd(usize),
    Trailer,
    Done,
    Failed(ChunkError),
}

/// Decodes one `aws-chunked` body from pieces of any size. With a signer, every chunk signature
/// and the trailer signature, when there is one, must match.
#[derive(Clone, Debug)]
pub struct ChunkDecoder {
    signer: Option<ChunkSigner>,
    state: State,
    /// The start of a header or trailer line that has no CRLF yet.
    line: Vec<u8>,
    chunk_hash: Sha256,
    trailers: String,
    decoded: u64,
}

impl ChunkDecoder {
    pub fn new(signer: Option<ChunkSigner>) -> Self {
        Self {
            signer,
            state: State::Header,
            line: Vec::new(),
            chunk_hash: Sha256::new(),
            trailers: String::new(),
            decoded: 0,
        }
    }

    /// Decodes the next bytes of the body. The data of the chunks goes to `data`, as slices of
    /// `input`. After an error, every call gives that error.
    pub fn push<'a>(
        &mut self,
        input: &'a [u8],
        data: &mut Vec<&'a [u8]>,
    ) -> Result<(), ChunkError> {
        if let State::Failed(e) = &self.state {
            return Err(e.clone());
        }
        let result = self.step(input, data);
        if let Err(e) = &result {
            self.state = State::Failed(e.clone());
        }
        result
    }

    /// The number of data bytes, once the whole body came. A body cut before its last chunk is
    /// [`ChunkError::Incomplete`].
    pub fn finish(&self) -> Result<u64, ChunkError> {
        match &self.state {
            State::Done => Ok(self.decoded),
            // Some clients end the body right after the line of the last chunk.
            State::Trailer if self.line.is_empty() && self.trailers.is_empty() => Ok(self.decoded),
            State::Trailer if self.line.is_empty() => Err(ChunkError::Malformed),
            State::Failed(e) => Err(e.clone()),
            _ => Err(ChunkError::Incomplete),
        }
    }

    fn step<'a>(
        &mut self,
        mut input: &'a [u8],
        data: &mut Vec<&'a [u8]>,
    ) -> Result<(), ChunkError> {
        while !input.is_empty() {
            match &mut self.state {
                State::Header | State::Trailer => {
                    let Some(end) = input.iter().position(|&b| b == b'\n') else {
                        self.add_to_line(input)?;
                        return Ok(());
                    };
                    self.add_to_line(&input[..=end])?;
                    input = &input[end + 1..];
                    self.end_line()?;
                }
                State::Data { left, .. } => {
                    let size = (*left).min(input.len() as u64) as usize;
                    let (piece, rest) = input.split_at(size);
                    *left -= size as u64;
                    self.chunk_hash.update(piece);
                    self.decoded += size as u64;
                    data.push(piece);
                    input = rest;
                    if *left == 0 {
                        self.end_data()?;
                    }
                }
                State::DataEnd(seen) => {
                    if input[0] != b"\r\n"[*seen] {
                        return Err(ChunkError::Malformed);
                    }
                    *seen += 1;
                    input = &input[1..];
                    if *seen == 2 {
                        self.state = State::Header;
                    }
                }
                State::Done => return Err(ChunkError::Malformed),
                State::Failed(e) => return Err(e.clone()),
            }
        }
        Ok(())
    }

    fn add_to_line(&mut self, bytes: &[u8]) -> Result<(), ChunkError> {
        // The CRLF does not count against the limit.
        if self.line.len() + bytes.len() > MAX_LINE + 2 {
            return Err(ChunkError::Malformed);
        }
        self.line.extend_from_slice(bytes);
        Ok(())
    }

    fn end_line(&mut self) -> Result<(), ChunkError> {
        let line = std::mem::take(&mut self.line);
        let text = line
            .strip_suffix(b"\r\n")
            .and_then(|text| std::str::from_utf8(text).ok())
            .ok_or(ChunkError::Malformed)?;
        match self.state {
            State::Header => self.header(text),
            _ => self.trailer(text),
        }
    }

    fn header(&mut self, text: &str) -> Result<(), ChunkError> {
        let (size, extension) = text.split_once(';').unwrap_or((text, ""));
        let size = u64::from_str_radix(size.trim(), 16).map_err(|_| ChunkError::Malformed)?;
        let signature = match self.signer {
            Some(_) => Some(
                extension
                    .strip_prefix("chunk-signature=")
                    .ok_or(ChunkError::BadSignature)?
                    .to_string(),
            ),
            None => None,
        };
        self.chunk_hash = Sha256::new();
        self.state = State::Data {
            left: size,
            signature,
        };
        if size == 0 {
            self.end_data()?;
            self.state = State::Trailer;
        }
        Ok(())
    }

    /// The data of a chunk is whole: check its signature.
    fn end_data(&mut self) -> Result<(), ChunkError> {
        let State::Data { signature, .. } = std::mem::replace(&mut self.state, State::DataEnd(0))
        else {
            unreachable!("end_data runs in the data state");
        };
        let hash = hex::encode(std::mem::take(&mut self.chunk_hash).finalize());
        if let (Some(signer), Some(given)) = (self.signer.as_mut(), signature)
            && !same_signature(&signer.sign_chunk_digest(&hash), &given)
        {
            return Err(ChunkError::BadSignature);
        }
        Ok(())
    }

    /// After the last chunk: trailer lines, an optional trailer signature, then an empty line.
    fn trailer(&mut self, text: &str) -> Result<(), ChunkError> {
        if text.is_empty() {
            self.state = State::Done;
            return Ok(());
        }
        if let Some(given) = text.strip_prefix("x-amz-trailer-signature:") {
            let signer = self.signer.as_mut().ok_or(ChunkError::BadSignature)?;
            if !same_signature(&signer.sign_trailer(&self.trailers), given.trim()) {
                return Err(ChunkError::BadSignature);
            }
            return Ok(());
        }
        if self.trailers.len() + text.len() + 1 > MAX_TRAILERS {
            return Err(ChunkError::Malformed);
        }
        self.trailers.push_str(text);
        self.trailers.push('\n');
        Ok(())
    }
}

/// Decodes a whole `aws-chunked` body.
pub fn decode_chunked(body: &[u8], signer: Option<ChunkSigner>) -> Result<Vec<u8>, ChunkError> {
    let mut decoder = ChunkDecoder::new(signer);
    let mut data = Vec::new();
    decoder.push(body, &mut data)?;
    decoder.finish()?;
    Ok(data.concat())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigv4::{ChunkSigner, encode_chunked, signing_key};

    fn signer() -> ChunkSigner {
        ChunkSigner {
            key: signing_key("secret", "20261030", "us-east-1"),
            timestamp: "20261030T000000Z".to_string(),
            scope: "20261030/us-east-1/s3/aws4_request".to_string(),
            previous: "00".repeat(32),
        }
    }

    /// Feeds `body` cut at `cuts`, and returns the decoded data or the first error.
    fn run(body: &[u8], cuts: &[usize], signed: bool) -> Result<Vec<u8>, ChunkError> {
        let mut decoder = ChunkDecoder::new(signed.then(signer));
        let mut out = Vec::new();
        let mut start = 0;
        for &end in cuts.iter().chain([&body.len()]) {
            let mut data = Vec::new();
            decoder.push(&body[start..end], &mut data)?;
            data.iter().for_each(|piece| out.extend_from_slice(piece));
            start = end;
        }
        let decoded = decoder.finish()?;
        assert_eq!(decoded, out.len() as u64);
        Ok(out)
    }

    /// Cut points from a small deterministic generator.
    fn random_cuts(len: usize, seed: u64) -> Vec<usize> {
        let mut state = seed | 1;
        let mut cuts: Vec<usize> = (0..8)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state % (len as u64 + 1)) as usize
            })
            .collect();
        cuts.sort_unstable();
        cuts
    }

    fn bodies() -> Vec<(&'static str, Vec<u8>, bool)> {
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let signed = encode_chunked(&data, 1024, Some(signer()));
        let mut forged = signed.clone();
        let at = forged.len() / 2;
        forged[at] ^= 1;
        let trailer = b"5\r\nhello\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n".to_vec();
        let mut after_end = encode_chunked(b"abc", 2, None);
        after_end.extend_from_slice(b"\r\nextra");
        vec![
            ("signed", signed.clone(), true),
            ("unsigned", encode_chunked(&data, 700, None), false),
            ("trailer", trailer, false),
            (
                "ends after the last chunk line",
                b"3\r\nabc\r\n0\r\n".to_vec(),
                false,
            ),
            ("forged", forged, true),
            ("no signature", encode_chunked(&data, 1024, None), true),
            ("cut", signed[..signed.len() - 90].to_vec(), true),
            ("bad size", b"zz\r\nabc\r\n0\r\n\r\n".to_vec(), false),
            (
                "no CRLF after data",
                b"3\r\nabcX\n0\r\n\r\n".to_vec(),
                false,
            ),
            ("bytes after the end", after_end, false),
        ]
    }

    #[test]
    fn test_pieces_of_one_byte_and_random_splits_give_the_whole_body_result() {
        for (name, body, signed) in bodies() {
            let whole = run(&body, &[], signed);
            let one_byte: Vec<usize> = (1..body.len()).collect();

            assert_eq!(run(&body, &one_byte, signed), whole, "{name}: one byte");
            for seed in 0..64 {
                let cuts = random_cuts(body.len(), seed);
                assert_eq!(run(&body, &cuts, signed), whole, "{name}: {cuts:?}");
            }
        }
    }

    #[test]
    fn test_each_body_decodes_or_fails_as_expected() {
        let results: Vec<(&str, Result<usize, ChunkError>)> = bodies()
            .into_iter()
            .map(|(name, body, signed)| (name, run(&body, &[], signed).map(|data| data.len())))
            .collect();

        assert_eq!(
            results,
            [
                ("signed", Ok(5000)),
                ("unsigned", Ok(5000)),
                ("trailer", Ok(5)),
                ("ends after the last chunk line", Ok(3)),
                ("forged", Err(ChunkError::BadSignature)),
                ("no signature", Err(ChunkError::BadSignature)),
                ("cut", Err(ChunkError::Incomplete)),
                ("bad size", Err(ChunkError::Malformed)),
                ("no CRLF after data", Err(ChunkError::Malformed)),
                ("bytes after the end", Err(ChunkError::Malformed)),
            ]
        );
    }

    #[test]
    fn test_declared_chunk_of_4_gib_reserves_nothing_and_ends_incomplete() {
        let mut decoder = ChunkDecoder::new(None);
        let mut data = Vec::new();

        decoder.push(b"100000000\r\n0123456789", &mut data).unwrap();

        assert_eq!(data, [b"0123456789".as_slice()]);
        assert_eq!(decoder.finish(), Err(ChunkError::Incomplete));
    }

    #[test]
    fn test_long_header_line_and_long_trailers_are_malformed() {
        let mut long_header = b"1;".to_vec();
        long_header.extend(std::iter::repeat_n(b'x', MAX_LINE + 1));
        let mut long_trailers = b"0\r\n".to_vec();
        for _ in 0..MAX_TRAILERS / 30 + 1 {
            long_trailers.extend_from_slice(b"x-amz-meta-a:aaaaaaaaaaaaaaaaa\r\n");
        }

        for body in [long_header, long_trailers] {
            let one_byte: Vec<usize> = (1..body.len()).collect();
            let mut decoder = ChunkDecoder::new(None);
            let mut failed = None;
            for window in body.chunks(1) {
                if let Err(e) = decoder.push(window, &mut Vec::new()) {
                    failed = Some(e);
                    break;
                }
            }

            assert_eq!(failed, Some(ChunkError::Malformed));
            assert_eq!(run(&body, &one_byte, false), Err(ChunkError::Malformed));
        }
    }

    #[test]
    fn test_push_after_an_error_gives_the_same_error() {
        let mut decoder = ChunkDecoder::new(None);

        let first = decoder.push(b"zz\r\n", &mut Vec::new());
        let second = decoder.push(b"3\r\nabc\r\n", &mut Vec::new());

        assert_eq!(first, Err(ChunkError::Malformed));
        assert_eq!(second, first);
        assert_eq!(decoder.finish(), first.map(|()| 0));
    }
}
