//! Listen command implementation
//!
//! Handles the user-client (trusted device) mode for receiving and
//! approving connection requests from remote clients.

use std::process::Command;

use bw_proxy::{IdentityFingerprint, ProxyClientConfig};
use bw_rat_client::{
    DefaultProxyClient, IdentityProvider, SessionStore, UserClient, UserClientEvent,
    UserClientResponse, UserCredentialData,
};
use clap::Args;
use color_eyre::eyre::{Result, bail};
use inquire::{Confirm, Select};
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::info;

use super::util::format_relative_time;
use crate::storage::{FileIdentityStorage, FileSessionCache};

const DEFAULT_PROXY_URL: &str = "ws://localhost:8080";

/// Arguments for the listen command
#[derive(Args)]
pub struct ListenArgs {
    /// Proxy server URL
    #[arg(long, default_value = DEFAULT_PROXY_URL)]
    pub proxy_url: String,

    /// Use PSK (Pre-Shared Key) mode instead of rendezvous code
    #[arg(long)]
    pub psk: bool,
}

impl ListenArgs {
    /// Execute the listen command
    pub async fn run(self) -> Result<()> {
        // Run interactive session
        run_user_client_session(self.proxy_url, self.psk).await
    }
}

/// Bitwarden CLI login item structure
#[derive(Deserialize)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Option<Vec<BwUri>>,
}

/// Bitwarden CLI URI structure
#[derive(Deserialize)]
struct BwUri {
    uri: Option<String>,
}

/// Bitwarden CLI item structure
#[derive(Deserialize)]
struct BwItem {
    login: Option<BwLogin>,
}

/// Look up a credential from the Bitwarden CLI
fn lookup_credential(domain: &str) -> Option<UserCredentialData> {
    // Try to find bw on PATH first, then fall back to homebrew location
    let bw_path = which_bw().unwrap_or_else(|| "/opt/homebrew/bin/bw".to_string());

    let output = Command::new(&bw_path)
        .args(["get", "item", domain])
        .output()
        .ok()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("Not found") {
            info!("bw get item failed: {}", stderr);
        }
        return None;
    }

    let item: BwItem = serde_json::from_slice(&output.stdout).ok()?;
    let login = item.login?;

    // Get the first URI if available
    let uri = login
        .uris
        .as_ref()
        .and_then(|uris| uris.first())
        .and_then(|u| u.uri.clone());

    Some(UserCredentialData {
        username: login.username,
        password: login.password,
        totp: login.totp,
        uri,
        notes: None,
    })
}

/// Find bw executable on PATH
fn which_bw() -> Option<String> {
    Command::new("which")
        .arg("bw")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

type SessionInfo = (IdentityFingerprint, Option<String>, u64, u64);

/// Print the session list with an optional pending entry
fn print_session_list(sessions: &[SessionInfo], pending_label: Option<&str>) {
    let mut sorted = sessions.to_vec();
    sorted.sort_by(|a, b| b.3.cmp(&a.3));

    println!("Listening for incoming requests from:");
    for (fingerprint, _, cached_at, last_connected_at) in &sorted {
        let short_hex = hex::encode(fingerprint.0)
            .chars()
            .take(12)
            .collect::<String>();
        let created_time = format_relative_time(*cached_at);
        let last_used_time = format_relative_time(*last_connected_at);
        println!(
            "  * Session {short_hex}  (created: {created_time}, last used: {last_used_time})"
        );
    }
    if let Some(label) = pending_label {
        println!("  * {label}");
    }
    println!();
}

/// Handle a single event from the user client
async fn handle_listen_event(
    event: UserClientEvent,
    response_tx: &mpsc::Sender<UserClientResponse>,
    sessions: &[SessionInfo],
) -> Result<()> {
    match event {
        UserClientEvent::Listening {} => {
            // Handled by the caller based on context
        }

        UserClientEvent::RendevouzCodeGenerated { code } => {
            println!("\n========================================");
            println!("  RENDEZVOUS CODE");
            println!("========================================");
            println!("  {code}");
            println!("========================================\n");
            println!("Share this code with your remote device.\n");

            print_session_list(sessions, Some("New session  (awaiting connection)"));
            println!("(Press Ctrl+C to exit)\n");
        }

        UserClientEvent::PskTokenGenerated { token } => {
            println!("\n========================================");
            println!("  PSK TOKEN (COPY ENTIRE TOKEN)");
            println!("========================================");
            println!("  {token}");
            println!("========================================\n");
            println!("Share this token securely with the remote device.\n");

            print_session_list(sessions, Some("New session  (awaiting connection)"));
            println!("(Press Ctrl+C to exit)\n");
        }

        UserClientEvent::HandshakeStart {} => {
            println!("Noise handshake started");
        }

        UserClientEvent::HandshakeProgress { message } => {
            eprintln!("Handshake progress: {message}");
        }

        UserClientEvent::HandshakeComplete {} => {
            println!("Secure channel established");
        }

        UserClientEvent::HandshakeFingerprint { fingerprint } => {
            println!("\n========================================");
            println!("  SECURITY VERIFICATION REQUIRED");
            println!("========================================");
            println!("  Handshake Fingerprint: {fingerprint}");
            println!("========================================");
            println!("\nPlease compare this fingerprint with the");
            println!("one shown on the remote device.");
            println!("They must match EXACTLY.\n");

            let approved = Confirm::new("Do the fingerprints match?")
                .with_default(false)
                .prompt()
                .unwrap_or(false);

            response_tx
                .send(UserClientResponse::VerifyFingerprint { approved })
                .await
                .ok();
        }

        UserClientEvent::FingerprintVerified {} => {
            println!("Fingerprint verified successfully!\n");
        }

        UserClientEvent::FingerprintRejected { reason } => {
            println!("Fingerprint rejected: {reason}\n");
            println!("Connection from remote device was refused.\n");
        }

        UserClientEvent::CredentialRequest {
            domain,
            request_id,
            session_id,
        } => {
            println!("\n--- Credential Request ---");
            println!("  Domain: {domain}");

            // Look up credential from Bitwarden CLI
            match lookup_credential(&domain) {
                Some(credential) => {
                    println!(
                        "  Found: {} ({})",
                        credential.username.as_deref().unwrap_or("no username"),
                        credential.uri.as_deref().unwrap_or("no uri")
                    );
                    println!();

                    let approved = Confirm::new(&format!("Send credential for {domain}?"))
                        .with_default(false)
                        .prompt()
                        .unwrap_or(false);

                    if approved {
                        response_tx
                            .send(UserClientResponse::RespondCredential {
                                request_id,
                                session_id: session_id.clone(),
                                approved: true,
                                credential: Some(credential),
                            })
                            .await
                            .ok();

                        println!("Credential sent for {domain}\n");
                    } else {
                        response_tx
                            .send(UserClientResponse::RespondCredential {
                                request_id,
                                session_id: session_id.clone(),
                                approved: false,
                                credential: None,
                            })
                            .await
                            .ok();

                        println!("Credential denied for {domain}\n");
                    }
                }
                None => {
                    println!("  No credential found in vault");
                    println!();

                    response_tx
                        .send(UserClientResponse::RespondCredential {
                            request_id,
                            session_id,
                            approved: false,
                            credential: None,
                        })
                        .await
                        .ok();

                    println!("No credential available for {domain}\n");
                }
            }
        }

        UserClientEvent::CredentialApproved { domain } => {
            eprintln!("Credential approved: {domain}");
        }

        UserClientEvent::CredentialDenied { domain } => {
            eprintln!("Credential denied: {domain}");
        }

        UserClientEvent::ClientDisconnected {} => {
            println!("Client disconnected");
        }

        UserClientEvent::Error { message, context } => {
            let ctx = context.as_deref().unwrap_or("unknown");
            println!("Error ({ctx}): {message}");
        }
    }

    Ok(())
}

/// Run the user client interactive session
async fn run_user_client_session(proxy_url: String, psk_mode: bool) -> Result<()> {
    let local = tokio::task::LocalSet::new();

    local
        .run_until(async move {
            // Create identity provider and session store
            let identity_provider = FileIdentityStorage::load_or_generate("user_client")?;
            let session_store = FileSessionCache::load_or_create("user_client")?;

            // Check for cached sessions
            let cached_sessions = session_store.list_sessions();

            if !cached_sessions.is_empty() {
                // Display cached sessions
                print_session_list(&cached_sessions, None);

                // Start listening for cached sessions immediately
                let (event_tx, mut event_rx) = mpsc::channel(32);
                let (response_tx, response_rx) = mpsc::channel(32);

                let proxy_client = Box::new(DefaultProxyClient::new(ProxyClientConfig {
                    proxy_url: proxy_url.clone(),
                    identity_keypair: Some(identity_provider.identity().to_owned()),
                }));

                let client_handle = tokio::task::spawn_local(async move {
                    let mut client = UserClient::listen(
                        Box::new(identity_provider) as Box<dyn IdentityProvider>,
                        Box::new(session_store) as Box<dyn SessionStore>,
                        proxy_client,
                    )
                    .await?;
                    client.listen_cached_only(event_tx, response_rx).await
                });

                // Run the prompt concurrently via spawn_blocking
                let mut prompt_handle = tokio::task::spawn_blocking(|| {
                    Select::new(
                        "Select an option (or wait for requests):",
                        vec!["Keep listening", "Create new session", "Exit"],
                    )
                    .prompt()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| "Keep listening".to_string())
                });

                // Multiplex events and prompt result
                let mut selection = None;
                loop {
                    tokio::select! {
                        event = event_rx.recv() => {
                            match event {
                                Some(event) => {
                                    handle_listen_event(event, &response_tx, &cached_sessions).await?;
                                }
                                None => {
                                    // Client channel closed
                                    break;
                                }
                            }
                        }
                        result = &mut prompt_handle => {
                            selection = Some(result.unwrap_or_else(|_| "Keep listening".to_string()));
                            break;
                        }
                    }
                }

                match selection.as_deref() {
                    Some("Create new session") => {
                        // Abort the cached-only listener and restart with rendezvous/psk
                        client_handle.abort();

                        let identity_provider = Box::new(
                            FileIdentityStorage::load_or_generate("user_client")?,
                        );
                        let session_store =
                            Box::new(FileSessionCache::load_or_create("user_client")?);

                        let (event_tx, mut event_rx) = mpsc::channel(32);
                        let (response_tx, response_rx) = mpsc::channel(32);

                        let proxy_client = Box::new(DefaultProxyClient::new(ProxyClientConfig {
                            proxy_url,
                            identity_keypair: Some(identity_provider.identity().to_owned()),
                        }));

                        let client_handle = tokio::task::spawn_local(async move {
                            let mut client =
                                UserClient::listen(identity_provider, session_store, proxy_client)
                                    .await?;
                            if psk_mode {
                                client.enable_psk(event_tx, response_rx).await
                            } else {
                                client.enable_rendezvous(event_tx, response_rx).await
                            }
                        });

                        // Normal event loop for the new session
                        while let Some(event) = event_rx.recv().await {
                            handle_listen_event(event, &response_tx, &cached_sessions).await?;
                        }

                        match client_handle.await {
                            Ok(Ok(())) => {
                                println!("\nUser client session ended.");
                                Ok(())
                            }
                            Ok(Err(e)) => bail!("User client error: {}", e),
                            Err(e) if e.is_cancelled() => {
                                println!("\nUser client session ended.");
                                Ok(())
                            }
                            Err(e) => bail!("Task error: {}", e),
                        }
                    }
                    Some("Exit") => {
                        client_handle.abort();
                        Ok(())
                    }
                    _ => {
                        // "Keep listening" or prompt closed — continue with the existing listener
                        while let Some(event) = event_rx.recv().await {
                            handle_listen_event(event, &response_tx, &cached_sessions).await?;
                        }

                        match client_handle.await {
                            Ok(Ok(())) => {
                                println!("\nUser client session ended.");
                                Ok(())
                            }
                            Ok(Err(e)) => bail!("User client error: {}", e),
                            Err(e) if e.is_cancelled() => {
                                println!("\nUser client session ended.");
                                Ok(())
                            }
                            Err(e) => bail!("Task error: {}", e),
                        }
                    }
                }
            } else {
                // No cached sessions — go straight to rendezvous/psk
                let (event_tx, mut event_rx) = mpsc::channel(32);
                let (response_tx, response_rx) = mpsc::channel(32);

                let identity_provider = Box::new(identity_provider);
                let session_store = Box::new(session_store);

                let proxy_client = Box::new(DefaultProxyClient::new(ProxyClientConfig {
                    proxy_url,
                    identity_keypair: Some(identity_provider.identity().to_owned()),
                }));

                let client_handle = tokio::task::spawn_local(async move {
                    let mut client =
                        UserClient::listen(identity_provider, session_store, proxy_client).await?;
                    if psk_mode {
                        client.enable_psk(event_tx, response_rx).await
                    } else {
                        client.enable_rendezvous(event_tx, response_rx).await
                    }
                });

                while let Some(event) = event_rx.recv().await {
                    handle_listen_event(event, &response_tx, &cached_sessions).await?;
                }

                match client_handle.await {
                    Ok(Ok(())) => {
                        println!("\nUser client session ended.");
                        Ok(())
                    }
                    Ok(Err(e)) => bail!("User client error: {}", e),
                    Err(e) if e.is_cancelled() => {
                        println!("\nUser client session ended.");
                        Ok(())
                    }
                    Err(e) => bail!("Task error: {}", e),
                }
            }
        })
        .await
}
