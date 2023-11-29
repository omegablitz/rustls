use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use helpers::KB;
use rustls::client::{ClientConnectionData, UnbufferedClientConnection};
use rustls::unbuffered::{
    AppDataRecord, ConnectionState, EncodeError, EncryptError, MayEncryptAppData, UnbufferedStatus,
};
#[allow(unused_imports)]
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, RootCertStore};
use rustls_examples as helpers;

// tokio
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// async-std
// to switch the runtime modify `Cargo.toml` and the `main` attribute below
// use async_std::io::{ReadExt, WriteExt};
// use async_std::net::TcpStream;

/* example configuration */
// remote server
const CERTFILE: Option<&str> = None;
const SERVER_NAME: &str = "example.com";
const PORT: u16 = 443;

const INCOMING_TLS_BUFSIZ: usize = 16 * KB;
const OUTGOING_TLS_INITIAL_BUFSIZ: usize = KB;

const MAX_ITERATIONS: usize = 20;

#[tokio::main(flavor = "current_thread")]
// #[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    //let config = ClientConfig::builder_with_protocol_versions(&[&TLS12])
    let config = ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .with_root_certificates(build_root_store()?)
        .with_no_client_auth();

    let config = Arc::new(config);

    let mut incoming_tls = [0; INCOMING_TLS_BUFSIZ];
    let mut outgoing_tls = vec![0; OUTGOING_TLS_INITIAL_BUFSIZ];

    converse(&config, &mut incoming_tls, &mut outgoing_tls).await?;

    Ok(())
}

async fn converse(
    config: &Arc<ClientConfig>,
    incoming_tls: &mut [u8],
    outgoing_tls: &mut Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut conn = UnbufferedClientConnection::new(Arc::clone(config), SERVER_NAME.try_into()?)?;
    let mut sock = TcpStream::connect(format!("{SERVER_NAME}:{PORT}")).await?;

    let mut incoming_used = 0;
    let mut outgoing_used = 0;

    let mut open_connection = true;
    let mut sent_request = false;
    let mut received_response = false;

    let mut iter_count = 0;
    while open_connection {
        let UnbufferedStatus { mut discard, state } =
            conn.process_tls_records(&mut incoming_tls[..incoming_used])?;

        match dbg!(state) {
            ConnectionState::AppDataAvailable(mut state) => {
                while let Some(res) = state.next_record() {
                    let AppDataRecord {
                        discard: new_discard,
                        payload,
                    } = res?;
                    discard += new_discard;

                    if payload.starts_with(b"HTTP") {
                        let response = core::str::from_utf8(payload)?;
                        let header = response
                            .lines()
                            .next()
                            .unwrap_or(response);

                        println!("{header}");
                    } else {
                        println!("(.. continued HTTP response ..)");
                    }

                    received_response = true;
                }
            }

            ConnectionState::MustEncodeTlsData(mut state) => {
                helpers::try_or_resize_and_retry(
                    |out_buffer| state.encode(out_buffer),
                    |e| {
                        if let EncodeError::InsufficientSize(is) = &e {
                            Ok(*is)
                        } else {
                            Err(e.into())
                        }
                    },
                    outgoing_tls,
                    &mut outgoing_used,
                )?;
            }

            ConnectionState::MustTransmitTlsData(mut state) => {
                if let Some(mut may_encrypt) = state.may_encrypt_app_data() {
                    encrypt_http_request(
                        &mut sent_request,
                        &mut may_encrypt,
                        outgoing_tls,
                        &mut outgoing_used,
                    );
                }

                send_tls(&mut sock, outgoing_tls, &mut outgoing_used).await?;
                state.done();
            }

            ConnectionState::NeedsMoreTlsData { .. } => {
                recv_tls(&mut sock, incoming_tls, &mut incoming_used).await?;
            }

            ConnectionState::TrafficTransit(mut may_encrypt) => {
                if encrypt_http_request(
                    &mut sent_request,
                    &mut may_encrypt,
                    outgoing_tls,
                    &mut outgoing_used,
                ) {
                    send_tls(&mut sock, outgoing_tls, &mut outgoing_used).await?;
                    recv_tls(&mut sock, incoming_tls, &mut incoming_used).await?;
                } else if !received_response {
                    // this happens in the TLS 1.3 case. the app-data was sent in the preceding
                    // `MustTransmitTlsData` state. the server should have already a response which
                    // we can read out from the socket
                    recv_tls(&mut sock, incoming_tls, &mut incoming_used).await?;
                } else {
                    helpers::try_or_resize_and_retry(
                        |out_buffer| may_encrypt.queue_close_notify(out_buffer),
                        |e| {
                            if let EncryptError::InsufficientSize(is) = &e {
                                Ok(*is)
                            } else {
                                Err(e.into())
                            }
                        },
                        outgoing_tls,
                        &mut outgoing_used,
                    )?;
                    send_tls(&mut sock, outgoing_tls, &mut outgoing_used).await?;
                    open_connection = false;
                }
            }

            ConnectionState::ConnectionClosed => {
                open_connection = false;
            }

            // other states are not expected in this example
            _ => unreachable!(),
        }

        if discard != 0 {
            assert!(discard <= incoming_used);

            incoming_tls.copy_within(discard..incoming_used, 0);
            incoming_used -= discard;

            eprintln!("discarded {discard}B from `incoming_tls`");
        }

        iter_count += 1;
        assert!(
            iter_count < MAX_ITERATIONS,
            "did not get a HTTP response within {MAX_ITERATIONS} iterations"
        );
    }

    assert!(sent_request);
    assert!(received_response);
    assert_eq!(0, incoming_used);
    assert_eq!(0, outgoing_used);

    Ok(())
}

async fn recv_tls(
    sock: &mut TcpStream,
    incoming_tls: &mut [u8],
    incoming_used: &mut usize,
) -> Result<(), Box<dyn Error>> {
    let read = sock
        .read(&mut incoming_tls[*incoming_used..])
        .await?;
    eprintln!("received {read}B of data");
    *incoming_used += read;
    Ok(())
}

async fn send_tls(
    sock: &mut TcpStream,
    outgoing_tls: &[u8],
    outgoing_used: &mut usize,
) -> Result<(), Box<dyn Error>> {
    sock.write_all(&outgoing_tls[..*outgoing_used])
        .await?;
    eprintln!("sent {outgoing_used}B of data");
    *outgoing_used = 0;
    Ok(())
}

fn encrypt_http_request(
    sent_request: &mut bool,
    may_encrypt: &mut MayEncryptAppData<'_, ClientConnectionData>,
    outgoing_tls: &mut [u8],
    outgoing_used: &mut usize,
) -> bool {
    if !*sent_request {
        let written = may_encrypt
            .encrypt(&build_http_request(), &mut outgoing_tls[*outgoing_used..])
            .expect("encrypted request does not fit in `outgoing_tls`");
        *outgoing_used += written;
        *sent_request = true;
        eprintln!("queued HTTP request");
        true
    } else {
        false
    }
}

fn build_root_store() -> Result<RootCertStore, Box<dyn Error>> {
    let mut root_store = RootCertStore::empty();
    if let Some(path) = CERTFILE {
        let certfile = File::open(path)?;
        let mut reader = BufReader::new(certfile);
        root_store.add_parsable_certificates(
            rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?,
        );
    } else {
        root_store.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        );
    }
    Ok(root_store)
}

fn build_http_request() -> Vec<u8> {
    format!("GET / HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n").into_bytes()
}
