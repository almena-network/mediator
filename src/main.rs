use almena_node::{Config, config::LogFormat, router};
use anyhow::Result;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env()?;
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return healthcheck(&config);
    }
    init_tracing(config.log_format);

    let listener = TcpListener::bind(config.bind).await?;
    tracing::info!(addr = %listener.local_addr()?, version = env!("CARGO_PKG_VERSION"), "almena node listening");

    axum::serve(listener, router())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("almena node stopped");
    Ok(())
}

/// `almena-node healthcheck`: exits 0 if `/health` answers 200. Used by the
/// container healthcheck, since the runtime image ships no curl.
fn healthcheck(config: &Config) -> Result<()> {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpStream};
    use std::time::Duration;

    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), config.bind.port());
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    anyhow::ensure!(
        response.starts_with("HTTP/1.1 200"),
        "unhealthy: {}",
        response.lines().next().unwrap_or("")
    );
    Ok(())
}

/// Log level comes from `RUST_LOG` (default `info`).
fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match format {
        LogFormat::Pretty => builder.init(),
        LogFormat::Json => builder.json().init(),
    }
}

/// Resolves on Ctrl+C or SIGTERM (what `docker stop` sends).
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for Ctrl+C");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to listen for SIGTERM")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
