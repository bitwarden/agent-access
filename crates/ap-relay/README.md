# ap-relay

A WebSocket relay server for `aac` (ap-cli) that routes messages between authenticated clients without access to message contents.

> [!IMPORTANT]
> This relay is not hardened for production. There are known reliability & safety improvements to be made.  

For the client library, see [`ap-relay-client`](../ap-relay-client/).
For shared protocol types, see [`ap-relay-protocol`](../ap-relay-protocol/).

## Quick Start

### Running the Relay Server

```bash
cargo run --bin ap-relay
```

The server will start listening on `ws://localhost:8080` by default.

### Embedding in Your Application

```rust
use ap_relay::server::RelayServer;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let server = RelayServer::new(addr);
    server.run().await?;
    Ok(())
}
```

## Architecture

The relay implements a three-phase protocol:

### 1. Authentication Phase

- Client connects to relay via WebSocket
- Server sends a cryptographic challenge
- Client signs the challenge with its cryptographic identity
- Server verifies the signature and authenticates the client
- This establishes the client's identity

### 2. Rendezvous Phase (Optional)

- Clients can request temporary pairing tokens (e.g., "ABC-DEF-GHI")
- Other clients can look up an identity by providing the code
- Enables peer discovery without sharing long-lived identifiers

### 3. Messaging Phase

- Authenticated clients can send messages to other clients by fingerprint
- Messages are routed through the relay server
- The relay validates the source identity but cannot decrypt message contents
