//! Support code for the engine tests.

use std::cell::RefCell;
use std::sync::{Arc, Mutex, Once};

thread_local! {
    /// Where the events of this thread go while a capture runs.
    static BUFFER: RefCell<Option<Arc<Mutex<Vec<u8>>>>> = const { RefCell::new(None) };
}

/// The log lines of this thread, for tests of the ERROR and WARN lines.
pub struct Logs {
    text: Arc<Mutex<Vec<u8>>>,
}

struct Writer;

impl std::io::Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        BUFFER.with(|buffer| {
            if let Some(text) = buffer.borrow().as_ref() {
                text.lock().unwrap().extend_from_slice(bytes);
            }
        });
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Captures every event on this thread until the result drops. A test on a current-thread
/// runtime sees the events of its engine. One global subscriber: a scoped one misses events
/// when other test threads reach a callsite first.
pub fn capture() -> Logs {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(|| Writer)
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("no other global subscriber");
    });
    let text = Arc::new(Mutex::new(Vec::new()));
    BUFFER.with(|buffer| *buffer.borrow_mut() = Some(text.clone()));
    Logs { text }
}

impl Drop for Logs {
    fn drop(&mut self) {
        BUFFER.with(|buffer| *buffer.borrow_mut() = None);
    }
}

impl Logs {
    /// The lines that hold `needle`.
    pub fn lines(&self, needle: &str) -> Vec<String> {
        let text = self.text.lock().unwrap();
        String::from_utf8_lossy(&text)
            .lines()
            .filter(|line| line.contains(needle))
            .map(str::to_string)
            .collect()
    }
}
