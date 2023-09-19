//! Example of utilizing IronRDP server.

#[macro_use]
extern crate tracing;

use anyhow::Context as _;
use ironrdp::server::{DisplayUpdate, KeyboardEvent, MouseEvent, RdpServer, RdpServerDisplay, RdpServerInputHandler};
use ironrdp_connector::DesktopSize;
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{
    fs::File,
    io::BufReader,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio_rustls::TlsAcceptor;

const HELP: &str = "\
USAGE:
  cargo run --example=server -- --host <HOSTNAME> --port <PORT>
";

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let action = match parse_args() {
        Ok(action) => action,
        Err(e) => {
            println!("{HELP}");
            return Err(e.context("invalid argument(s)"));
        }
    };

    setup_logging()?;

    match action {
        Action::ShowHelp => {
            println!("{HELP}");
            Ok(())
        }
        Action::Run { host, port, cert, key } => run(host, port, cert, key).await,
    }
}

#[derive(Debug)]
enum Action {
    ShowHelp,
    Run {
        host: String,
        port: u16,
        cert: Option<String>,
        key: Option<String>,
    },
}

fn parse_args() -> anyhow::Result<Action> {
    let mut args = pico_args::Arguments::from_env();

    let action = if args.contains(["-h", "--help"]) {
        Action::ShowHelp
    } else {
        let host = args.opt_value_from_str("--host")?.unwrap_or(String::from("localhost"));
        let port = args.opt_value_from_str("--port")?.unwrap_or(3389);
        let cert = args.opt_value_from_str("--cert")?;
        let key = args.opt_value_from_str("--key")?;
        Action::Run { host, port, cert, key }
    };

    Ok(action)
}

fn setup_logging() -> anyhow::Result<()> {
    use tracing::metadata::LevelFilter;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::EnvFilter;

    let fmt_layer = tracing_subscriber::fmt::layer().compact();

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::WARN.into())
        .with_env_var("IRONRDP_LOG")
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(env_filter)
        .try_init()
        .context("failed to set tracing global subscriber")?;

    Ok(())
}

fn acceptor(cert_path: &str, key_path: &str) -> anyhow::Result<TlsAcceptor> {
    let cert = certs(&mut BufReader::new(File::open(cert_path)?))?[0].clone();
    let key = pkcs8_private_keys(&mut BufReader::new(File::open(key_path)?))?[0].clone();

    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![rustls::Certificate(cert)], rustls::PrivateKey(key))
        .expect("bad certificate/key");

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

#[derive(Debug)]
struct InnerHandler {}

#[derive(Clone, Debug)]
struct Handler {
    inner: Arc<InnerHandler>,
}

impl Handler {
    fn new() -> Self {
        Self {
            inner: Arc::new(InnerHandler {}),
        }
    }
}

#[async_trait::async_trait]
impl RdpServerInputHandler for Handler {
    async fn keyboard(&mut self, event: KeyboardEvent) {
        info!(?event, "keyboard");
    }

    async fn mouse(&mut self, event: MouseEvent) {
        info!(?event, "mouse");
    }
}

#[async_trait::async_trait]
impl RdpServerDisplay for Handler {
    async fn size(&mut self) -> DesktopSize {
        info!("size");
        DesktopSize { width: 0, height: 0 }
    }

    async fn get_update(&mut self) -> Option<DisplayUpdate> {
        info!("get_update");
        None
    }
}

async fn run(host: String, port: u16, cert: Option<String>, key: Option<String>) -> anyhow::Result<()> {
    info!(host, port, cert, key, "run");
    let handler = Handler::new();

    let tls = cert
        .as_ref()
        .zip(key.as_ref())
        .map(|(cert, key)| acceptor(cert, key).unwrap());

    let addr = SocketAddr::new(host.parse::<IpAddr>()?, port);

    let server = RdpServer::builder().with_addr(addr);
    let server = if let Some(tls) = tls {
        server.with_tls(tls)
    } else {
        server.with_no_security()
    };
    let mut server = server
        .with_input_handler(handler.clone())
        .with_display_handler(handler.clone())
        .build();

    server.run().await
}
