#!/usr/bin/env python3
"""Example: connect to a listening peer and request a credential using UniFFI bindings.

Usage:
    # With rendezvous code:
    python connect_request.py --token ABC-DEF-GHI --domain example.com

    # With PSK token:
    python connect_request.py --token <64hex_psk>_<64hex_fingerprint> --domain example.com

    # With cached session:
    python connect_request.py --session <fingerprint_hex> --domain example.com

Setup:
    # Build the cdylib
    cargo build -p ap-uniffi

    # Generate Python bindings into this directory
    cargo run --bin uniffi-bindgen generate \
        --library target/debug/libap_uniffi.dylib \
        --language python --out-dir examples/uniffi/

    # Then run this script from the repo root
    python examples/uniffi/connect_request.py --token ABC-DEF-GHI --domain example.com
"""

import argparse
import json
import os
import sys

from ap_uniffi import (
    ConnectionStorage,
    FfiStoredConnection,
    IdentityStorage,
    RemoteAccessClient,
    RemoteAccessError,
    looks_like_psk_token,
)


class FileIdentityStorage(IdentityStorage):
    """Simple file-based identity storage."""

    def __init__(self, name: str, base_dir: str = "~/.access-protocol"):
        self._path = os.path.expanduser(f"{base_dir}/{name}.key")
        os.makedirs(os.path.dirname(self._path), exist_ok=True)

    def load_identity(self) -> bytes | None:
        try:
            with open(self._path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def save_identity(self, identity_bytes: bytes):
        with open(self._path, "wb") as f:
            f.write(identity_bytes)


class FileConnectionStorage(ConnectionStorage):
    """Simple file-based connection storage."""

    def __init__(self, name: str, base_dir: str = "~/.access-protocol"):
        self._path = os.path.expanduser(f"{base_dir}/connections_{name}.json")
        os.makedirs(os.path.dirname(self._path), exist_ok=True)

    def _load(self) -> list[dict]:
        try:
            with open(self._path) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _save_all(self, data: list[dict]):
        with open(self._path, "w") as f:
            json.dump(data, f, indent=2)

    def _to_record(self, d: dict) -> FfiStoredConnection:
        return FfiStoredConnection(
            fingerprint=d["fingerprint"],
            name=d.get("name"),
            cached_at=d["cached_at"],
            last_connected_at=d["last_connected_at"],
            transport_state=bytes(d["transport_state"]) if d.get("transport_state") else None,
        )

    def _to_dict(self, c: FfiStoredConnection) -> dict:
        return {
            "fingerprint": c.fingerprint,
            "name": c.name,
            "cached_at": c.cached_at,
            "last_connected_at": c.last_connected_at,
            "transport_state": list(c.transport_state) if c.transport_state else None,
        }

    def get(self, fingerprint_hex: str) -> FfiStoredConnection | None:
        for d in self._load():
            if d["fingerprint"] == fingerprint_hex:
                return self._to_record(d)
        return None

    def save(self, connection: FfiStoredConnection):
        data = self._load()
        data = [d for d in data if d["fingerprint"] != connection.fingerprint]
        data.append(self._to_dict(connection))
        self._save_all(data)

    def update(self, fingerprint_hex: str, last_connected_at: int):
        data = self._load()
        for d in data:
            if d["fingerprint"] == fingerprint_hex:
                d["last_connected_at"] = last_connected_at
        self._save_all(data)

    def list(self) -> list[FfiStoredConnection]:
        return [self._to_record(d) for d in self._load()]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Request a credential via Agent Access (UniFFI bindings)"
    )
    parser.add_argument("--proxy", default="ws://localhost:8080", help="Proxy server URL")
    parser.add_argument("--token", help="Rendezvous code or PSK token")
    parser.add_argument("--session", help="Cached session fingerprint (hex)")
    parser.add_argument("--domain", required=True, help="Domain to request credentials for")
    parser.add_argument("--identity", default="uniffi-remote", help="Identity name")
    args = parser.parse_args()

    try:
        identity_storage = FileIdentityStorage(args.identity)
        connection_storage = FileConnectionStorage(args.identity)

        client = RemoteAccessClient(
            proxy_url=args.proxy,
            identity_storage=identity_storage,
            connection_storage=connection_storage,
            event_handler=None,
        )

        # Step 1: Connect to the proxy
        client.connect()

        # Step 2: Establish a secure channel (consumer decides which mode)
        if args.token:
            if looks_like_psk_token(args.token):
                client.pair_with_psk(args.token)
            else:
                fp = client.pair_with_handshake(args.token)
                print(f"Handshake fingerprint: {fp}", file=sys.stderr)
        elif args.session:
            client.load_existing_connection(args.session)
        else:
            connections = connection_storage.list()
            if len(connections) == 1:
                client.load_existing_connection(connections[0].fingerprint)
            elif len(connections) == 0:
                print("No cached sessions. Provide --token to start a new connection.", file=sys.stderr)
                return 1
            else:
                print(f"Multiple cached sessions ({len(connections)}). Use --session to specify one:", file=sys.stderr)
                for c in connections:
                    name = c.name or "unnamed"
                    print(f"  {c.fingerprint[:16]}... ({name})", file=sys.stderr)
                return 1

        # Step 3: Request credential
        cred = client.request_credential(args.domain)
        client.close()

        if cred.username:
            print(f"Username: {cred.username}")
        if cred.password:
            print(f"Password: {cred.password}")
        if cred.totp:
            print(f"TOTP: {cred.totp}")
        if cred.uri:
            print(f"URI: {cred.uri}")
        if cred.notes:
            print(f"Notes: {cred.notes}")

        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
