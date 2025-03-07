use std::{
    ffi::c_void,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use crate::{
    config::{CertificateHash, Credential, CredentialFlags},
    Addr, BufferRef, Configuration, Connection, ConnectionEvent, ConnectionRef, CredentialConfig,
    Listener, Registration, RegistrationConfig, Settings, Status, Stream, StreamEvent, StreamRef,
    CONNECTION_SHUTDOWN_FLAG_NONE, SEND_FLAG_FIN, STREAM_OPEN_FLAG_NONE,
    STREAM_SHUTDOWN_FLAG_ABORT, STREAM_START_FLAG_NONE,
};

fn buffers_to_string(buffers: &[BufferRef]) -> String {
    let mut v = Vec::new();
    for b in buffers {
        v.extend_from_slice(b.as_bytes());
    }
    String::from_utf8_lossy(v.as_slice()).to_string()
}

/// Use pwsh to get the test cert hash
pub fn get_test_cert_hash() -> String {
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
    s
}

#[test]
fn test_server_client() {
    let cert_hash = get_test_cert_hash();

    let reg = Registration::new(&RegistrationConfig::default()).unwrap();
    let alpn = [BufferRef::from("qtest")];
    let settings = Settings::new()
        .set_ServerResumptionLevel(crate::ServerResumptionLevel::ResumeAndZerortt)
        .set_PeerBidiStreamCount(1);

    let config = Configuration::new(&reg, &alpn, Some(&settings)).unwrap();

    let cred_config = CredentialConfig::new()
        .set_credential_flags(CredentialFlags::NO_CERTIFICATE_VALIDATION)
        .set_credential(Credential::CertificateHash(
            CertificateHash::from_str(&cert_hash).unwrap(),
        ));
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
                        SEND_FLAG_FIN,
                        ctx.as_ref() as *const _ as *const c_void,
                    )
                }
                .is_err()
                {
                    let _ = stream.shutdown(STREAM_SHUTDOWN_FLAG_ABORT, 0);
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

    let mut l = Listener::new();
    l.open(&reg, move |_, ev| {
        println!("Server listener event: {ev:?}");
        match ev {
            crate::ListenerEvent::NewConnection {
                info: _,
                connection,
            } => {
                connection.set_callback_handler(conn_handler.clone());
                connection.set_configuration(&config_cp)?;
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
    let client_config = Configuration::new(&reg, &alpn, Some(&client_settings)).unwrap();
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
                        let mut s = Stream::new();
                        s.open(&conn, STREAM_OPEN_FLAG_NONE, stream_handler.clone())?;
                        s.start(STREAM_START_FLAG_NONE)?;
                        // BufferRef needs to be heap allocated
                        let b = "hello from client".as_bytes().to_vec();
                        let b_ref = Box::new([BufferRef::from((*b).as_ref())]);
                        let ctx = Box::new((b, b_ref));
                        unsafe {
                            s.send(
                                ctx.1.as_slice(),
                                SEND_FLAG_FIN,
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
                        conn.shutdown(CONNECTION_SHUTDOWN_FLAG_NONE, 0);
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
        let mut conn = Connection::new();
        conn.open(&reg, conn_handler).unwrap();

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
