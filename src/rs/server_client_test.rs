use std::{
    ffi::c_void,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    },
    time::Duration,
};

use crate::{
    config::{Credential, CredentialFlags},
    Addr, BufferRef, Configuration, Connection, ConnectionEvent, ConnectionRef,
    ConnectionShutdownFlags, CredentialConfig, Listener, Registration, RegistrationConfig,
    Settings, Status, Stream, StreamEvent, StreamRef,
};

fn buffers_to_string(buffers: &[BufferRef]) -> String {
    let mut v = Vec::new();
    for b in buffers {
        v.extend_from_slice(b.as_bytes());
    }
    String::from_utf8_lossy(v.as_slice()).to_string()
}

/// Use pwsh to get the test cert hash
#[cfg(target_os = "windows")]
pub fn get_test_cred() -> Credential {
    use crate::CertificateHash;
    let output = std::process::Command::new("pwsh.exe")
        .args(["-Command", "Get-ChildItem Cert:\\CurrentUser\\My | Where-Object -Property FriendlyName -EQ -Value MsQuicTestServer | Select-Object -ExpandProperty Thumbprint -First 1"]).
        output().expect("Failed to execute command");
    assert!(output.status.success());
    let mut s = String::from_utf8(output.stdout).unwrap();
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    };
    Credential::CertificateHash(CertificateHash::from_str(&s).unwrap())
}

#[cfg(not(target_os = "windows"))]
static CREATE_TEST_CERTS: std::sync::Once = std::sync::Once::new();

/// Generate a test cert if not present using openssl cli.
#[cfg(not(target_os = "windows"))]
pub fn get_test_cred() -> Credential {
    let cert_dir = std::env::temp_dir().join("msquic_test_rs");
    let key = "key.pem";
    let cert = "cert.pem";
    let key_path = cert_dir.join(key);
    let cert_path = cert_dir.join(cert);

    CREATE_TEST_CERTS.call_once(|| {
        // Nothing to do if certs are already present
        if key_path.exists() && cert_path.exists() {
            return;
        }

        // Remove any pre-existing files
        let _ = std::fs::remove_dir_all(&cert_dir);

        std::fs::create_dir_all(&cert_dir).expect("cannot create cert dir");
        // Generate test cert using openssl cli
        let output = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:4096",
                "-keyout",
                "key.pem",
                "-out",
                "cert.pem",
                "-sha256",
                "-days",
                "3650",
                "-nodes",
                "-subj",
                "/CN=localhost",
            ])
            .current_dir(cert_dir)
            .stderr(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .output()
            .expect("cannot generate cert");
        if !output.status.success() {
            panic!("generate cert failed");
        }
    });

    assert!(key_path.exists() && cert_path.exists());

    use crate::CertificateFile;
    Credential::CertificateFile(CertificateFile::new(
        key_path.display().to_string(),
        cert_path.display().to_string(),
    ))
}

#[test]
fn test_server_client() {
    let cred = get_test_cred();

    let reg = Registration::new(&RegistrationConfig::default()).unwrap();
    let alpn = [BufferRef::from("qtest")];
    let settings = Settings::new()
        .set_ServerResumptionLevel(crate::ServerResumptionLevel::ResumeAndZerortt)
        .set_PeerBidiStreamCount(1);

    let config = Configuration::open(&reg, &alpn, Some(&settings)).unwrap();

    let cred_config = CredentialConfig::new()
        .set_credential_flags(CredentialFlags::NO_CERTIFICATE_VALIDATION)
        .set_credential(cred);
    config.load_credential(&cred_config).unwrap();
    let config = Arc::new(config);
    let config_cp = config.clone();

    let (s_tx, s_rx) = std::sync::mpsc::channel::<String>();

    let stream_handler = move |stream: StreamRef, ev: StreamEvent| {
        println!("Server stream event: {ev:?}");
        match ev {
            StreamEvent::Receive {
                absolute_offset: _,
                total_buffer_length: _,
                buffers,
                flags: _,
            } => {
                // Send the result to main thread.
                let s = buffers_to_string(buffers);
                s_tx.send(s).unwrap();
            }
            StreamEvent::PeerSendShutdown { .. } => {
                // reply to client
                let b = "hello from server".as_bytes().to_vec();
                let b_ref = Box::new([BufferRef::from((*b).as_ref())]);
                let ctx = Box::new((b, b_ref));
                if unsafe {
                    stream.send(
                        ctx.1.as_ref(),
                        crate::SendFlags::FIN,
                        ctx.as_ref() as *const _ as *const c_void,
                    )
                }
                .is_err()
                {
                    let _ = stream.shutdown(crate::StreamShutdownFlags::ABORT, 0);
                } else {
                    // detach buffer
                    let _ = Box::into_raw(ctx);
                }
            }
            StreamEvent::SendComplete {
                cancelled: _,
                client_context,
            } => unsafe {
                let _ = Box::from_raw(client_context as *mut (Vec<u8>, Box<[BufferRef; 1]>));
            },
            StreamEvent::ShutdownComplete { .. } => {
                // auto close
                unsafe { Stream::from_raw(stream.as_raw()) };
            }
            _ => {}
        };
        Ok(())
    };

    let conn_handler = move |conn: ConnectionRef, ev: ConnectionEvent| {
        println!("Server connection event: {ev:?}");
        match ev {
            crate::ConnectionEvent::PeerStreamStarted { stream, flags: _ } => {
                stream.set_callback_handler(stream_handler.clone());
            }
            crate::ConnectionEvent::ShutdownComplete { .. } => {
                // auto close connection
                unsafe { Connection::from_raw(conn.as_raw()) };
            }
            _ => {}
        };
        Ok(())
    };

    let l = Listener::open(&reg, move |_, ev| {
        println!("Server listener event: {ev:?}");
        match ev {
            crate::ListenerEvent::NewConnection {
                info: _,
                connection,
            } => {
                connection.set_callback_handler(conn_handler.clone());
                connection.set_configuration(&config_cp)?;
                // Keep the connection alive; will be closed on ShutdownComplete.
                let _ = unsafe { connection.into_raw() };
            }
            crate::ListenerEvent::StopComplete {
                app_close_in_progress: _,
            } => {}
        }
        Ok(())
    })
    .unwrap();
    let local_address = Addr::from(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        4567,
    ));
    println!("Starting listener");
    l.start(&alpn, Some(&local_address)).unwrap();

    // create client and send msg
    let client_settings = Settings::new().set_IdleTimeoutMs(1000);
    let client_config = Configuration::open(&reg, &alpn, Some(&client_settings)).unwrap();
    {
        let cred_config = CredentialConfig::new_client()
            .set_credential_flags(CredentialFlags::NO_CERTIFICATE_VALIDATION);
        client_config.load_credential(&cred_config).unwrap();
    }

    let (c_tx, c_rx) = std::sync::mpsc::channel::<String>();
    {
        let stream_handler = move |stream: StreamRef, ev: StreamEvent| {
            println!("Client stream event: {ev:?}");
            match ev {
                StreamEvent::StartComplete { id, .. } => {
                    assert_eq!(stream.get_stream_id().unwrap(), id);
                }
                StreamEvent::SendComplete {
                    cancelled: _,
                    client_context,
                } => {
                    let _ = unsafe {
                        Box::from_raw(client_context as *mut (Vec<u8>, Box<[BufferRef; 1]>))
                    };
                }
                StreamEvent::Receive { buffers, .. } => {
                    // send the result to main thread.
                    let s = buffers_to_string(buffers);
                    c_tx.send(s).unwrap();
                }
                StreamEvent::ShutdownComplete { .. } => {
                    let _ = unsafe { Stream::from_raw(stream.as_raw()) };
                }
                _ => {}
            }
            Ok(())
        };

        let conn_handler = move |conn: ConnectionRef, ev: ConnectionEvent| {
            println!("Client connection event: {ev:?}");
            match ev {
                ConnectionEvent::Connected { .. } => {
                    // open stream and send
                    let f_send = || {
                        let s = Stream::open(
                            &conn,
                            crate::StreamOpenFlags::NONE,
                            stream_handler.clone(),
                        )?;
                        s.start(crate::StreamStartFlags::NONE)?;
                        // BufferRef needs to be heap allocated
                        let b = "hello from client".as_bytes().to_vec();
                        let b_ref = Box::new([BufferRef::from((*b).as_ref())]);
                        let ctx = Box::new((b, b_ref));
                        unsafe {
                            s.send(
                                ctx.1.as_slice(),
                                crate::SendFlags::FIN,
                                ctx.as_ref() as *const _ as *const c_void,
                            )
                        }?;
                        // detach the buffer
                        let _ = Box::into_raw(ctx);
                        // detach stream and let callback cleanup
                        unsafe { s.into_raw() };
                        Ok::<(), Status>(())
                    };
                    if f_send().is_err() {
                        println!("Client send failed");
                        conn.shutdown(crate::ConnectionShutdownFlags::NONE, 0);
                    }
                }
                ConnectionEvent::ShutdownComplete { .. } => {
                    // No need to close. Main function owns the handle.
                }
                _ => {}
            };
            Ok(())
        };

        println!("open client connection");
        let conn = Connection::open(&reg, conn_handler).unwrap();

        conn.start(&client_config, "127.0.0.1", 4567).unwrap();

        let server_s = s_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("Server failed receive request.");
        assert_eq!(server_s, "hello from client");
        let client_s = c_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("Client failed receive response.");
        assert_eq!(client_s, "hello from server");
    }
    l.stop();
}

#[test]
fn connection_ref_callback_cleanup() {
    struct DropGuard {
        counter: Arc<AtomicUsize>,
    }

    impl Drop for DropGuard {
        fn drop(&mut self) {
            self.counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    let cred = get_test_cred();

    let reg = Registration::new(&RegistrationConfig::default()).unwrap();
    let alpn = [BufferRef::from("qcleanup")];
    let settings = Settings::new()
        .set_ServerResumptionLevel(crate::ServerResumptionLevel::ResumeAndZerortt)
        .set_PeerBidiStreamCount(1);

    let server_config = Configuration::open(&reg, &alpn, Some(&settings)).unwrap();

    let cred_config = CredentialConfig::new()
        .set_credential_flags(CredentialFlags::NO_CERTIFICATE_VALIDATION)
        .set_credential(cred);
    server_config.load_credential(&cred_config).unwrap();
    let server_config = Arc::new(server_config);

    let drop_counter = Arc::new(AtomicUsize::new(0));

    let (conn_tx, conn_rx) = mpsc::channel::<Connection>();
    let listener = Listener::open(&reg, {
        let server_config = server_config.clone();
        let drop_counter = drop_counter.clone();
        let conn_tx = conn_tx.clone();
        move |_, ev| {
            if let crate::ListenerEvent::NewConnection { connection, .. } = ev {
                let callback_guard = DropGuard {
                    counter: drop_counter.clone(),
                };
                let conn_tx = conn_tx.clone();
                connection.set_callback_handler(
                    move |_conn: ConnectionRef, _ev: ConnectionEvent| {
                        // Reference the guard so it lives as long as the callback.
                        let _guard_ref = &callback_guard;
                        Ok(())
                    },
                );
                connection.set_configuration(&server_config)?;
                // Transfer ownership to the test so it can close the connection.
                let _ = conn_tx.send(connection);
            }
            Ok(())
        }
    })
    .unwrap();

    let local_address = Addr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
    listener.start(&alpn, Some(&local_address)).unwrap();
    let port = listener
        .get_local_addr()
        .unwrap()
        .as_socket()
        .unwrap()
        .port();

    let client_settings = Settings::new().set_IdleTimeoutMs(500);
    let client_config = Configuration::open(&reg, &alpn, Some(&client_settings)).unwrap();
    let cred_config = CredentialConfig::new_client()
        .set_credential_flags(CredentialFlags::NO_CERTIFICATE_VALIDATION);
    client_config.load_credential(&cred_config).unwrap();

    let (client_done_tx, client_done_rx) = mpsc::channel();
    let client_conn = Connection::open(&reg, {
        let client_done_tx = client_done_tx.clone();
        move |conn: ConnectionRef, ev: ConnectionEvent| {
            match ev {
                ConnectionEvent::Connected { .. } => {
                    conn.shutdown(ConnectionShutdownFlags::NONE, 0);
                }
                ConnectionEvent::ShutdownComplete { .. } => {
                    let _ = client_done_tx.send(());
                }
                _ => {}
            }
            Ok(())
        }
    })
    .unwrap();

    client_conn
        .start(&client_config, "127.0.0.1", port)
        .unwrap();

    // Receive the owned connection from the listener callback.
    let server_conn = conn_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("Server did not receive connection");
    client_done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("Client did not complete shutdown");

    // Drop the server connection to trigger cleanup of the callback context.
    // close_inner drops the context synchronously after ConnectionClose returns.
    drop(server_conn);

    assert_eq!(
        drop_counter.load(Ordering::SeqCst),
        1,
        "ConnectionRef callback context was not cleaned up"
    );
    listener.stop();
}
