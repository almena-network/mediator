//! Operational metrics in the Prometheus text format, served on their own
//! address (`ALMENA_METRICS_ADDR`) so they never go out through the public
//! proxy. Counters only count: no DIDs, nothing per mediation.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use axum::Router;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;

use crate::push::Service;

/// The process's metrics.
pub static METRICS: Metrics = Metrics::new();

/// Where a DIDComm message came in.
#[derive(Debug, Clone, Copy)]
pub enum Transport {
    Http,
    WebSocket,
}

/// What became of a DIDComm message.
#[derive(Debug, Clone, Copy)]
pub enum MessageOutcome {
    Accepted,
    Reply,
    Rejected,
}

/// What became of a `forward` payload.
#[derive(Debug, Clone, Copy)]
pub enum Forward {
    /// Queued for a recipient mediated here.
    Queued,
    /// Relayed to another mediator on the first attempt.
    Relayed,
    /// First relay attempt failed; stored for retries.
    RelayScheduled,
    /// First relay attempt failed and could not be stored.
    RelayDropped,
    /// Refused: malformed, unknown recipient, or queue full.
    Refused,
}

/// What became of a relay retry.
#[derive(Debug, Clone, Copy)]
pub enum Retry {
    Delivered,
    Rescheduled,
    Abandoned,
}

/// What became of a push.
#[derive(Debug, Clone, Copy)]
pub enum Push {
    Delivered,
    InvalidToken,
    Failed,
}

const TRANSPORTS: [(Transport, &str); 2] = [
    (Transport::Http, "http"),
    (Transport::WebSocket, "websocket"),
];
const OUTCOMES: [(MessageOutcome, &str); 3] = [
    (MessageOutcome::Accepted, "accepted"),
    (MessageOutcome::Reply, "reply"),
    (MessageOutcome::Rejected, "rejected"),
];
const FORWARDS: [(Forward, &str); 5] = [
    (Forward::Queued, "queued"),
    (Forward::Relayed, "relayed"),
    (Forward::RelayScheduled, "relay_scheduled"),
    (Forward::RelayDropped, "relay_dropped"),
    (Forward::Refused, "refused"),
];
const RETRIES: [(Retry, &str); 3] = [
    (Retry::Delivered, "delivered"),
    (Retry::Rescheduled, "rescheduled"),
    (Retry::Abandoned, "abandoned"),
];
const SERVICES: [(Service, &str); 2] = [(Service::Fcm, "fcm"), (Service::Apns, "apns")];
const PUSHES: [(Push, &str); 3] = [
    (Push::Delivered, "delivered"),
    (Push::InvalidToken, "invalid_token"),
    (Push::Failed, "failed"),
];

pub struct Metrics {
    messages: [[AtomicU64; 3]; 2],
    rate_limited: AtomicU64,
    forwards: [AtomicU64; 5],
    relay_retries: [AtomicU64; 3],
    pushes: [[AtomicU64; 3]; 2],
    live_sessions: AtomicI64,
    mediations_granted: AtomicU64,
    mediations_removed: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub const fn new() -> Self {
        Self {
            messages: [
                [const { AtomicU64::new(0) }; 3],
                [const { AtomicU64::new(0) }; 3],
            ],
            rate_limited: AtomicU64::new(0),
            forwards: [const { AtomicU64::new(0) }; 5],
            relay_retries: [const { AtomicU64::new(0) }; 3],
            pushes: [
                [const { AtomicU64::new(0) }; 3],
                [const { AtomicU64::new(0) }; 3],
            ],
            live_sessions: AtomicI64::new(0),
            mediations_granted: AtomicU64::new(0),
            mediations_removed: AtomicU64::new(0),
        }
    }

    pub fn message(&self, transport: Transport, outcome: MessageOutcome) {
        inc(&self.messages[transport as usize][outcome as usize], 1);
    }

    pub fn rate_limited(&self) {
        inc(&self.rate_limited, 1);
    }

    pub fn forward(&self, forward: Forward, count: u64) {
        inc(&self.forwards[forward as usize], count);
    }

    pub fn relay_retry(&self, retry: Retry) {
        inc(&self.relay_retries[retry as usize], 1);
    }

    pub fn push(&self, service: Service, push: Push) {
        let service = match service {
            Service::Fcm => 0,
            Service::Apns => 1,
        };
        inc(&self.pushes[service][push as usize], 1);
    }

    pub fn live_session_opened(&self) {
        self.live_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn live_session_closed(&self) {
        self.live_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn mediation_granted(&self) {
        inc(&self.mediations_granted, 1);
    }

    pub fn mediations_removed(&self, count: u64) {
        inc(&self.mediations_removed, count);
    }

    /// The Prometheus text exposition format (version 0.0.4).
    pub fn render(&self) -> String {
        let mut out = String::new();
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);

        family(
            &mut out,
            "almena_mediator_info",
            "gauge",
            "The running mediator.",
        );
        let _ = writeln!(
            out,
            "almena_mediator_info{{version=\"{}\"}} 1",
            crate::VERSION
        );

        family(
            &mut out,
            "almena_didcomm_messages_total",
            "counter",
            "DIDComm messages received, by transport and outcome.",
        );
        for (t, transport) in TRANSPORTS {
            for (o, outcome) in OUTCOMES {
                let _ = writeln!(
                    out,
                    "almena_didcomm_messages_total{{transport=\"{transport}\",outcome=\"{outcome}\"}} {}",
                    get(&self.messages[t as usize][o as usize])
                );
            }
        }

        family(
            &mut out,
            "almena_rate_limited_total",
            "counter",
            "Requests and WebSocket messages refused by the per-IP rate limit.",
        );
        let _ = writeln!(out, "almena_rate_limited_total {}", get(&self.rate_limited));

        family(
            &mut out,
            "almena_forwards_total",
            "counter",
            "Forwarded payloads, by what became of them.",
        );
        for (f, result) in FORWARDS {
            let _ = writeln!(
                out,
                "almena_forwards_total{{result=\"{result}\"}} {}",
                get(&self.forwards[f as usize])
            );
        }

        family(
            &mut out,
            "almena_relay_retries_total",
            "counter",
            "Retries of relays to other mediators, by result.",
        );
        for (r, result) in RETRIES {
            let _ = writeln!(
                out,
                "almena_relay_retries_total{{result=\"{result}\"}} {}",
                get(&self.relay_retries[r as usize])
            );
        }

        family(
            &mut out,
            "almena_pushes_total",
            "counter",
            "Push wake-ups, by service and result.",
        );
        for (i, (_, service)) in SERVICES.iter().enumerate() {
            for (p, result) in PUSHES {
                let _ = writeln!(
                    out,
                    "almena_pushes_total{{service=\"{service}\",result=\"{result}\"}} {}",
                    get(&self.pushes[i][p as usize])
                );
            }
        }

        family(
            &mut out,
            "almena_live_sessions",
            "gauge",
            "WebSocket sessions open now.",
        );
        let _ = writeln!(
            out,
            "almena_live_sessions {}",
            self.live_sessions.load(Ordering::Relaxed)
        );

        family(
            &mut out,
            "almena_mediations_granted_total",
            "counter",
            "mediate-request messages granted (a repeated request counts again).",
        );
        let _ = writeln!(
            out,
            "almena_mediations_granted_total {}",
            get(&self.mediations_granted)
        );

        family(
            &mut out,
            "almena_mediations_removed_total",
            "counter",
            "Mediations removed for being idle longer than ALMENA_MEDIATION_TTL.",
        );
        let _ = writeln!(
            out,
            "almena_mediations_removed_total {}",
            get(&self.mediations_removed)
        );
        out
    }
}

fn inc(counter: &AtomicU64, by: u64) {
    counter.fetch_add(by, Ordering::Relaxed);
}

fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
}

/// `GET /metrics`, for the metrics listener only.
pub fn router() -> Router {
    Router::new().route(
        "/metrics",
        get(|| async {
            (
                [(
                    header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8",
                )],
                METRICS.render(),
            )
                .into_response()
        }),
    )
}

/// Serves [`router`] on `addr` in the background.
pub async fn serve(addr: SocketAddr) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(addr = %listener.local_addr()?, "metrics listening");
    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router()).await {
            tracing::error!(error = %err, "metrics server stopped");
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_every_series_in_the_text_format() {
        let metrics = Metrics::new();
        metrics.message(Transport::WebSocket, MessageOutcome::Reply);
        metrics.forward(Forward::Queued, 3);
        metrics.push(Service::Apns, Push::InvalidToken);
        metrics.live_session_opened();
        let text = metrics.render();
        assert!(text.contains(
            "almena_didcomm_messages_total{transport=\"websocket\",outcome=\"reply\"} 1"
        ));
        assert!(
            text.contains("almena_didcomm_messages_total{transport=\"http\",outcome=\"reply\"} 0")
        );
        assert!(text.contains("almena_forwards_total{result=\"queued\"} 3"));
        assert!(text.contains("almena_pushes_total{service=\"apns\",result=\"invalid_token\"} 1"));
        assert!(text.contains("almena_live_sessions 1"));
        // Every sample belongs to a family announced with HELP and TYPE.
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let name = line.split(['{', ' ']).next().unwrap();
            assert!(text.contains(&format!("# TYPE {name} ")), "{name}");
        }
    }
}
