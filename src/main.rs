use anyhow::Result;
use tls::server::{
    connection::handle_connection,
    server::{Config, load_cert, load_rsa_keys},
};

use std::net::TcpListener;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("trace")
        .pretty()
        .init();

    let certificate = load_cert("cert.cer")?;
    let (private_key, public_key) = load_rsa_keys("key.der")?;

    let config = Config {
        certificate,
        private_key,
        public_key,
    };

    let listener = TcpListener::bind("0.0.0.0:3001")?;

    for conn in listener.incoming().filter_map(Result::ok) {
        _ = handle_connection(&config, conn)
            .inspect_err(|e| tracing::error!("TLS connection handle error: {e:?}"));
    }

    Ok(())
}
