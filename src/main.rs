use std::{
    io::{Error, ErrorKind},
    pin::Pin,
    time::Duration,
};

use clap::Parser;
use openssl::ssl::{
    Ssl, SslContext, SslContextBuilder, SslMethod, SslMode, SslOptions, SslVersion,
};
use tokio::{
    io::{split, stdin, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, Lines},
    net::TcpStream,
    runtime, select,
    signal::ctrl_c,
    sync::mpsc,
    time::{sleep, sleep_until, timeout, Instant},
};
use tokio_openssl::SslStream;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
struct Args {
    #[arg(short = 's', long)]
    irc_server: String,

    #[arg(short = 't', long)]
    use_tls: bool,

    #[arg(short = 'n', long)]
    nick: String,

    #[arg(short = 'c', long)]
    channel: String,
}

fn main() {
    {
        tracing_subscriber::fmt::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .init();

        let orig_panic_hook = std::panic::take_hook();

        std::panic::set_hook(Box::new(move |panic_info| {
            orig_panic_hook(panic_info);
            std::process::exit(1);
        }));
    }

    let args = Args::parse();

    let rt = runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();

    rt.block_on(async {
        let (sender, receiver) = mpsc::channel::<String>(1000);

        select! {
            ret = stdin_source(sender) => {
                error!("error from stdin_source(): {:?}", ret);
            },
            ret = irc_sink(receiver, args.irc_server, args.use_tls, args.nick, args.channel) => {
                error!("error from irc_sink(): {:?}", ret);
            },
            ret = ctrl_c() => {
                ret.expect("failed to listen for Ctrl-C");

                println!("Ctrl-C received, shutting down");
            },
        }
    });

    // We need this because of https://github.com/tokio-rs/tokio/issues/2466
    // ("Stdin can block shutdown #2466").
    rt.shutdown_timeout(Duration::from_secs(1));
}

async fn stdin_source(sender: mpsc::Sender<String>) -> Result<(), Error> {
    let mut lines = BufReader::new(stdin()).lines();

    loop {
        select! {
            ret = lines.next_line() => {
                sender
                    .send(
                        ret.map_err(|err| {
                            Error::other(format!("error reading line from stdin: {}", err))
                        })?
                        .ok_or_else(|| {
                            Error::new(ErrorKind::UnexpectedEof, "EOF reading line from stdin")
                        })?,
                    )
                    .await
                    .map_err(|err| {
                        Error::new(
                            ErrorKind::BrokenPipe,
                            format!("error writing line from stdin to output channel: {}", err),
                        )
                    })?;
            },
            _ = sender.closed() => {
                return Err(Error::from(ErrorKind::BrokenPipe));
            },
        }
    }
}

const IRC_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IRC_NICK_USER_PHASE_LENGTH: Duration = Duration::from_secs(5);
const IRC_PING_INTERVAL: Duration = Duration::from_secs(60);
const IRC_PONG_TIMEOUT: Duration = Duration::from_secs(120);
const IRC_RECONNECT_WAIT: Duration = Duration::from_secs(1);

async fn irc_sink(
    mut receiver: mpsc::Receiver<String>,
    server: String,
    use_tls: bool,
    nick: String,
    channel: String,
) {
    loop {
        if let Err(err) =
            irc_sink_connect_once(&mut receiver, &server, use_tls, &nick, &channel).await
        {
            info!("error from irc_sink_connect_once(): {:?}", err);
        }

        sleep(IRC_RECONNECT_WAIT).await;
    }
}

async fn irc_sink_connect_once(
    receiver: &mut mpsc::Receiver<String>,
    server: &str,
    use_tls: bool,
    nick: &str,
    channel: &str,
) -> Result<(), Error> {
    let stream = timeout(IRC_CONNECT_TIMEOUT, TcpStream::connect(server))
        .await
        .unwrap_or_else(|_| Err(Error::from(ErrorKind::TimedOut)))
        .map_err(|err| Error::other(format!("error connecting to {}: {}", server, err)))?;

    if use_tls {
        let ssl_ctx = irc_sink_ssl_context()
            .map_err(|err| Error::other(format!("error creating SSL context: {}", err)))?;

        let ssl = Ssl::new(&ssl_ctx)
            .map_err(|err| Error::other(format!("error creating SSL: {}", err)))?;

        let mut tls_stream = SslStream::new(ssl, stream)
            .map_err(|err| Error::other(format!("error creating SSL stream: {}", err)))?;

        Pin::new(&mut tls_stream)
            .connect()
            .await
            .map_err(|err| Error::other(format!("error performing TLS handshake: {}", err)))?;

        let (reader, writer) = split(tls_stream);

        irc_sink_exchange(receiver, reader, writer, nick, channel).await
    } else {
        let (reader, writer) = split(stream);

        irc_sink_exchange(receiver, reader, writer, nick, channel).await
    }
}

async fn irc_sink_exchange<T, U>(
    receiver: &mut mpsc::Receiver<String>,
    reader: T,
    mut writer: U,
    nick: &str,
    channel: &str,
) -> Result<(), Error>
where
    T: AsyncRead + Unpin,
    U: AsyncWrite + Unpin,
{
    let mut lines = BufReader::new(reader).lines();

    writer
        .write_all(format!("NICK {}\r\nUSER {} * * :{}\r\n", nick, nick, nick).as_bytes())
        .await
        .map_err(|err| Error::other(format!("error writing NICK/USER line: {}", err)))?;

    if let Ok(ret) = timeout(IRC_NICK_USER_PHASE_LENGTH, irc_sink_log_lines(&mut lines)).await {
        ret.map_err(|err| {
            Error::other(format!(
                "error reading line during NICK/USER phase: {}",
                err
            ))
        })?;
    }

    debug!("finished waiting for NICK/USER response");

    writer
        .write_all(format!("JOIN #{}\r\n", channel).as_bytes())
        .await
        .map_err(|err| Error::other(format!("error writing JOIN line: {}", err)))?;

    let mut last_line_received = Instant::now();
    let mut send_next_ping = last_line_received + IRC_PING_INTERVAL;

    loop {
        select! {
            ret = lines.next_line() => {
                let line = ret
                    .map_err(|err| {
                        Error::other(format!("error reading line from IRC server: {}", err))
                    })?
                    .ok_or_else(|| {
                        Error::new(ErrorKind::UnexpectedEof, "EOF reading line from IRC server")
                    })?;

                debug!("got from IRC server: {}", line);

                last_line_received = Instant::now();
                send_next_ping = last_line_received + IRC_PING_INTERVAL;

                if line.len() >= 4 && &line[0..3] == "PING" {
                    writer
                        .write_all("PONG\r\n".as_bytes())
                        .await
                        .map_err(|err| Error::other(format!("error writing PONG line: {}", err)))?;
                }
            },
            msg = receiver.recv() => {
                let msg = msg
                    .ok_or_else(|| Error::from(ErrorKind::UnexpectedEof))
                    .map_err(|err| {
                        Error::other(format!(
                            "error reading message from message channel: {}",
                            err
                        ))
                    })?;

                debug!("sending {}", msg);

                writer
                    .write_all(format!("PRIVMSG #{} :{}\r\n", channel, msg).as_bytes())
                    .await
                    .map_err(|err| Error::other(format!("error writing PRIVMSG line: {}", err)))?;
            },
            _ = sleep_until(send_next_ping) => {
                debug!("sending PING");

                send_next_ping = Instant::now() + IRC_PING_INTERVAL;

                writer
                    .write_all("PING :me\r\n".as_bytes())
                    .await
                    .map_err(|err| Error::other(format!("error writing PING line: {}", err)))?;
            },
            _ = sleep_until(last_line_received + IRC_PONG_TIMEOUT) => {
                return Err(Error::new(ErrorKind::TimedOut, "timeout reading from IRC server"));
            }
        }
    }
}

fn irc_sink_ssl_context() -> Result<SslContext, Error> {
    let mut builder = SslContextBuilder::new(SslMethod::tls_client())
        .map_err(|err| Error::other(format!("error creating SSL context builder: {}", err)))?;

    builder.set_mode(
        SslMode::RELEASE_BUFFERS
            | SslMode::AUTO_RETRY
            | SslMode::ACCEPT_MOVING_WRITE_BUFFER
            | SslMode::ENABLE_PARTIAL_WRITE,
    );

    builder.set_options(
        (SslOptions::ALL | SslOptions::NO_COMPRESSION | SslOptions::NO_SSL_MASK)
            & !SslOptions::NO_TLSV1_3,
    );

    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|err| {
            Error::other(format!(
                "error setting SSL context builder min proto version: {}",
                err
            ))
        })?;

    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|err| {
            Error::other(format!(
                "error setting SSL context builder max proto version: {}",
                err
            ))
        })?;

    Ok(builder.build())
}

async fn irc_sink_log_lines<T>(lines: &mut Lines<BufReader<T>>) -> Result<(), Error>
where
    T: AsyncRead + Unpin,
{
    loop {
        debug!(
            "got line during NICK/USER phase: {}",
            lines
                .next_line()
                .await
                .map_err(|err| Error::other(format!("error reading line: {}", err)))?
                .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "EOF reading line"))?
        );
    }
}
