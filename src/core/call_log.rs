//! Async write queue for the per-call audit log (`ati_call_log`).
//!
//! Architecture mirrors LiteLLM's spend-log pipeline: bounded `mpsc::channel`
//! between request handlers and a single flush task that batches inserts.
//! Three invariants:
//!
//!   1. **Never block the request path.** Senders use `try_send`. When the
//!      channel is full, drops are counted and a warning is rate-limited; the
//!      handler returns immediately.
//!   2. **Never panic the flush task.** All sqlx errors are logged and
//!      swallowed. The pool reconnects automatically; transient outages
//!      cost a batch, not the whole audit pipeline.
//!   3. **JSONL audit is the source of truth.** This module is purely
//!      additive — `core::audit::append` writes the on-disk JSONL line
//!      first, then we enqueue the DB row. A DB outage cannot regress the
//!      existing on-disk audit.
//!
//! The entire module is gated behind `#[cfg(feature = "db")]` because the
//! `sqlx` dependency is itself an optional Cargo feature.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sqlx::{PgPool, QueryBuilder};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Bounded channel capacity. ~20 MB worst-case heap at ~2 KB per row, ~16
/// minutes of buffer at 10 rps. Bumped beyond LiteLLM's default 100 because
/// ATI rows carry larger payloads (full request_args + response metadata).
pub const CHANNEL_CAPACITY: usize = 10_000;

/// How often the flush task pushes a partial batch to Postgres. Caps the p99
/// audit-row latency without forcing a write per request.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum batch size per `INSERT`. With 18 columns × 500 rows = 9k bind
/// params, well under PG's 65k cap. Larger batches give better throughput;
/// smaller batches give better lossiness on shutdown.
pub const MAX_BATCH: usize = 500;

/// One row, ready to be written to `ati_call_log`.
#[derive(Debug, Clone)]
pub struct CallLogEntry {
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub ended_at: chrono::DateTime<chrono::Utc>,
    pub latency_ms: i64,
    pub token_hash: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub endpoint: &'static str,
    pub tool_name: Option<String>,
    pub provider: Option<String>,
    pub handler: Option<&'static str>,
    pub status: &'static str,
    pub upstream_status: Option<i32>,
    pub error_class: Option<&'static str>,
    pub error_message: Option<String>,
    pub request_args: serde_json::Value,
    pub response_size: Option<i32>,
    pub requester_ip: Option<String>,
    pub user_agent: Option<String>,
}

/// Sender side of the audit queue. Stored on `ProxyState`; cheap to clone
/// (internally `Arc`s).
#[derive(Clone)]
pub struct CallLogSink {
    tx: mpsc::Sender<CallLogEntry>,
    dropped: Arc<AtomicU64>,
}

impl CallLogSink {
    /// Enqueue an entry. Non-blocking. On full channel, increments the drop
    /// counter and emits a rate-limited `tracing::warn!`.
    pub fn enqueue(&self, entry: CallLogEntry) {
        if self.tx.try_send(entry).is_err() {
            // Channel full or closed. Bump counter; warn every 1024th drop
            // so we don't flood logs during sustained backpressure.
            let prev = self.dropped.fetch_add(1, Ordering::Relaxed);
            if prev.is_multiple_of(1024) {
                tracing::warn!(
                    dropped_total = prev + 1,
                    "ati_call_log channel full or closed; dropping audit row"
                );
            }
        }
    }

    /// Total number of audit rows dropped over the lifetime of this sink.
    /// Surfaced via `/health` so operators can spot saturation.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Spawn the flush task and return a sender. The proxy stores the `CallLogSink`
/// on `ProxyState`; the `JoinHandle` is dropped (the task ends naturally when
/// every `CallLogSink` clone is dropped, which closes the channel).
pub fn spawn(pool: PgPool) -> (CallLogSink, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let sink = CallLogSink {
        tx,
        dropped: Arc::new(AtomicU64::new(0)),
    };
    let handle = tokio::spawn(run_flush_task(rx, pool));
    (sink, handle)
}

/// Drain the queue forever, batching writes by `MAX_BATCH` or `FLUSH_INTERVAL`.
async fn run_flush_task(mut rx: mpsc::Receiver<CallLogEntry>, pool: PgPool) {
    let mut buf: Vec<CallLogEntry> = Vec::with_capacity(MAX_BATCH);
    let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
    // First tick fires immediately; skip it so we don't issue a bogus empty
    // flush on startup before any traffic arrives.
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if !buf.is_empty() {
                    flush(&pool, &mut buf).await;
                }
            }
            maybe = rx.recv() => match maybe {
                Some(entry) => {
                    buf.push(entry);
                    if buf.len() >= MAX_BATCH {
                        flush(&pool, &mut buf).await;
                    }
                }
                None => {
                    // All senders dropped — proxy is shutting down. Best-effort
                    // final flush, then exit cleanly.
                    if !buf.is_empty() {
                        flush(&pool, &mut buf).await;
                    }
                    break;
                }
            }
        }
    }
}

/// Flush `buf` to Postgres in a single multi-row INSERT. Always clears `buf`,
/// success or failure — at-most-once delivery is the contract.
async fn flush(pool: &PgPool, buf: &mut Vec<CallLogEntry>) {
    let count = buf.len();

    // 18 columns excluding the auto-generated request_id PK. INET cast applied
    // to the requester_ip text so we don't need the optional `ipnetwork` sqlx
    // feature.
    let mut q = QueryBuilder::<sqlx::Postgres>::new(
        "INSERT INTO ati_call_log (\
            started_at, ended_at, latency_ms, \
            token_hash, user_id, session_id, \
            endpoint, tool_name, provider, handler, \
            status, upstream_status, error_class, error_message, \
            request_args, response_size, requester_ip, user_agent\
        ) ",
    );
    q.push_values(buf.drain(..), |mut b, e| {
        b.push_bind(e.started_at)
            .push_bind(e.ended_at)
            .push_bind(e.latency_ms)
            .push_bind(e.token_hash)
            .push_bind(e.user_id)
            .push_bind(e.session_id)
            .push_bind(e.endpoint)
            .push_bind(e.tool_name)
            .push_bind(e.provider)
            .push_bind(e.handler)
            .push_bind(e.status)
            .push_bind(e.upstream_status)
            .push_bind(e.error_class)
            .push_bind(e.error_message)
            .push_bind(e.request_args)
            .push_bind(e.response_size)
            .push(" CAST(")
            .push_bind_unseparated(e.requester_ip)
            .push_unseparated(" AS INET)")
            .push_bind(e.user_agent);
    });

    if let Err(err) = q.build().execute(pool).await {
        tracing::warn!(
            error = %err,
            count,
            "ati_call_log flush failed; batch dropped"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_entry(tag: &str) -> CallLogEntry {
        CallLogEntry {
            started_at: chrono::Utc::now(),
            ended_at: chrono::Utc::now(),
            latency_ms: 0,
            token_hash: None,
            user_id: Some(tag.to_string()),
            session_id: None,
            endpoint: "/call",
            tool_name: None,
            provider: None,
            handler: None,
            status: "success",
            upstream_status: None,
            error_class: None,
            error_message: None,
            request_args: serde_json::Value::Null,
            response_size: None,
            requester_ip: None,
            user_agent: None,
        }
    }

    /// Direct test on the sink: bounded(2) accepts 2, drops the rest.
    #[tokio::test]
    async fn enqueue_drops_when_full() {
        let (tx, _rx) = mpsc::channel::<CallLogEntry>(2);
        let sink = CallLogSink {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        };

        sink.enqueue(dummy_entry("a"));
        sink.enqueue(dummy_entry("b"));
        // Channel is now full; the next 3 should drop.
        sink.enqueue(dummy_entry("c"));
        sink.enqueue(dummy_entry("d"));
        sink.enqueue(dummy_entry("e"));

        assert_eq!(sink.dropped_count(), 3);
    }

    /// Sink is cheap to clone; the drop counter is shared across clones.
    #[tokio::test]
    async fn dropped_counter_is_shared_across_clones() {
        let (tx, _rx) = mpsc::channel::<CallLogEntry>(1);
        let sink_a = CallLogSink {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        };
        let sink_b = sink_a.clone();

        sink_a.enqueue(dummy_entry("a"));
        // Channel full; both these drop.
        sink_a.enqueue(dummy_entry("b"));
        sink_b.enqueue(dummy_entry("c"));

        assert_eq!(sink_a.dropped_count(), 2);
        assert_eq!(sink_b.dropped_count(), 2);
    }

    /// After all senders drop, the receiver sees None — flush task exits cleanly.
    #[tokio::test]
    async fn channel_closes_when_sink_dropped() {
        let (tx, mut rx) = mpsc::channel::<CallLogEntry>(4);
        let sink = CallLogSink {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        };
        sink.enqueue(dummy_entry("a"));
        drop(sink);
        // First recv returns the entry, second returns None (channel closed).
        assert!(rx.recv().await.is_some());
        assert!(rx.recv().await.is_none());
    }
}
