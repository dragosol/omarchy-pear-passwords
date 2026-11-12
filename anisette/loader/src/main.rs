//! Pear Passwords' anisette server.
//!
//! Since October 2026 Apple's GrandSlam checks that the platform a client names in
//! X-Mme-Client-Info is the platform of the ADI library that made its one-time password, and
//! it no longer serves Apple ID sign-in to Android clients at all. So this loads Apple's own
//! Windows ADI, CoreADI64.dll from iCloud for Windows, through apple-crates' library-coreadi,
//! and Pear signs in as the Windows iCloud client it then really is.
//!
//! It runs under Wine inside the anisette container. It provisions the machine with Apple once
//! (CoreADI keeps that state in the Wine prefix, which lives in a podman volume) and then
//! answers every GET / with a fresh set of machine headers, in the JSON shape Pear's
//! backend/icp/auth/anisette.py reads. Nothing else is served.

use adi::proxy::ADIProxy;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use grandslam::bundle_information::BundleInformation;
use grandslam::device::Device;
use grandslam::http_session::AnisetteHTTPSession;
use library_coreadi::windows::{device_identifier, WindowsCoreADIProxy};
use std::error::Error;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

/// The account-independent DSID anisette data is requested for.
const DSID: i64 = -2;

/// The identity provisioning presents. It has to describe the same platform as the ADI
/// (Windows) and the same client Pear later names in X-Mme-Client-Info (iCloud for Windows,
/// the package CoreADI64.dll comes from). Pear's own client info is in backend/icp/const.py.
const OPERATING_SYSTEM: &str = "Windows;6.2(0,0);9200";
const BUNDLE: BundleInformation<'static> = BundleInformation {
    bundle_name: "iCloud",
    bundle_identifier: "com.apple.iCloud",
    bundle_version: "15.10.0.39",
};

struct Options {
    dll: PathBuf,
    bind: IpAddr,
    port: u16,
}

fn options() -> Result<Options, String> {
    let mut options = Options {
        dll: PathBuf::from("CoreADI64.dll"),
        bind: IpAddr::from([127, 0, 0, 1]),
        port: 6969,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--dll" => options.dll = PathBuf::from(value()?),
            "--bind" => options.bind = value()?.parse().map_err(|_| "invalid --bind address")?,
            "--port" => options.port = value()?.parse().map_err(|_| "invalid --port")?,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(options)
}

/// An error with every cause under it: reqwest's own message ("builder error") names none.
fn chain(error: &dyn Error) -> String {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(next) = cause {
        text.push_str(": ");
        text.push_str(&next.to_string());
        cause = next.source();
    }
    text
}

/// Provision the machine with Apple unless CoreADI says it already is. Provisioning talks to
/// gsa.apple.com through grandslam, over TLS verified against the system roots and Apple Root CA.
fn ensure_provisioned(proxy: &WindowsCoreADIProxy, device_id: &str) -> Result<(), String> {
    if proxy
        .is_machine_provisioned(DSID)
        .map_err(|e| format!("is_machine_provisioned: {e}"))?
    {
        eprintln!("anisette: machine already provisioned");
        return Ok(());
    }
    eprintln!("anisette: provisioning this machine with Apple");
    let device = Device {
        device_model: "PC".to_string(),
        operating_system_information: OPERATING_SYSTEM.to_string(),
        device_uuid: device_id.to_string(),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio: {e}"))?;
    runtime.block_on(async {
        let http = grandslam::http_session(device, BUNDLE)
            .await
            .map_err(|e| format!("cannot reach Apple: {}", chain(&e)))?;
        grandslam::provision(&AnisetteHTTPSession::new(http, proxy))
            .await
            .map_err(|e| format!("provisioning failed: {}", chain(&e)))
    })?;
    eprintln!("anisette: provisioned");
    Ok(())
}

fn machine_headers(proxy: &dyn ADIProxy, device_id: &str) -> Result<String, String> {
    let (mid, otp) = proxy
        .request_otp(DSID)
        .map_err(|e| format!("request_otp: {e}"))?;
    let routing = proxy
        .get_idms_routing(DSID)
        .map_err(|e| format!("get_idms_routing: {e}"))?;
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    // X-Apple-I-MD-LU and the serial are left to Pear: its device record supplies a stable
    // local-user id per store, and that id is also the client id Pear gives iCloud setup.
    Ok(serde_json::json!({
        "X-Apple-I-MD": BASE64_STANDARD.encode(otp),
        "X-Apple-I-MD-M": BASE64_STANDARD.encode(mid),
        "X-Apple-I-MD-RINFO": routing.to_string(),
        "X-Mme-Device-Id": device_id,
        "X-Apple-I-Client-Time": now,
        "X-Apple-I-TimeZone": "UTC",
        "X-Apple-Locale": "en_US",
        "X-Apple-I-SRL-NO": "0",
    })
    .to_string())
}

fn answer(stream: &mut TcpStream, proxy: &WindowsCoreADIProxy, device_id: &str) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut request = [0u8; 2048];
    let read = stream.read(&mut request)?;
    let line = String::from_utf8_lossy(&request[..read]);
    let mut words = line.split_whitespace();
    let (method, path) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
    let (status, body) = match (method, path) {
        ("GET", "/") => match machine_headers(proxy, device_id) {
            Ok(body) => ("200 OK", body),
            Err(error) => {
                eprintln!("anisette: {error}");
                ("503 Service Unavailable", serde_json::json!({ "error": error }).to_string())
            }
        },
        ("GET", "/healthz") => ("200 OK", r#"{"status":"ok"}"#.to_string()),
        _ => ("404 Not Found", r#"{"error":"not found"}"#.to_string()),
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

fn run() -> Result<(), String> {
    let options = options()?;
    let proxy = WindowsCoreADIProxy::open(&options.dll)
        .map_err(|e| format!("cannot load {}: {e}", options.dll.display()))?;
    let device_id = device_identifier();
    eprintln!("anisette: device {device_id}");
    ensure_provisioned(&proxy, &device_id)?;
    let listener = TcpListener::bind((options.bind, options.port))
        .map_err(|e| format!("cannot listen on {}:{}: {e}", options.bind, options.port))?;
    eprintln!("anisette: serving on {}:{}", options.bind, options.port);
    // One request at a time: CoreADI is not documented as thread-safe, and the daemon asks
    // for at most a handful of header sets per sign-in or sync.
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(error) = answer(&mut stream, &proxy, &device_id) {
                    eprintln!("anisette: request failed: {error}");
                }
            }
            Err(error) => eprintln!("anisette: accept failed: {error}"),
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("anisette: {error}");
        std::process::exit(1);
    }
}
