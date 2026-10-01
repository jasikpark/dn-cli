use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::mpsc;
use std::thread;

/// Answer one request with an empty host list, sending back the request's
/// `User-Agent` header value.
fn serve() -> (String, mpsc::Receiver<Option<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut user_agent = None;
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap() > 2 {
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("user-agent")
            {
                user_agent = Some(value.trim().to_string());
            }
            line.clear();
        }
        let body = r#"{"data":[],"metadata":{}}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        tx.send(user_agent).unwrap();
    });
    (url, rx)
}

#[test]
fn requests_identify_the_client_by_version_and_repository() {
    let (url, rx) = serve();
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_dn"))
        .args(["hosts", "list"])
        .env("DN_CONFIG_DIR", dir.path())
        .env("DEFINED_API_URL", &url)
        .env("DEFINED_API_KEY", "fake-test-key")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let expected = format!(
        "dn-cli/{} (+https://github.com/jasikpark/dn-cli)",
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(rx.recv().unwrap().as_deref(), Some(expected.as_str()));
}
