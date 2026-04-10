#!/usr/bin/env python3
"""Interactive test script for UniFFI Python bindings.

Usage:
    python test.py --token <PSK_TOKEN> --domain github.com
    python test.py --domain github.com              # uses cached session
"""

import argparse
import json
import os
import sys
sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))

from ap_uniffi import (
    ConnectionStorage,
    FfiStoredConnection,
    IdentityStorage,
    RemoteAccessClient,
    RemoteAccessError,
    looks_like_psk_token,
)

PROXY = "wss://ap.lesspassword.dev"
IDENTITY = "test-python-uniffi"


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


def main():
    parser = argparse.ArgumentParser(description="Test UniFFI Python bindings")
    parser.add_argument("--token", help="PSK token or rendezvous code")
    parser.add_argument("--session", help="Cached session fingerprint (hex)")
    parser.add_argument("--domain", default="github.com", help="Domain to request")
    parser.add_argument("--proxy", default=PROXY, help="Proxy URL")
    parser.add_argument(
        "--identity", default=IDENTITY,
        help="Identity keypair name — stored at ~/.access-protocol/<name>.key",
    )
    args = parser.parse_args()

    identity_storage = FileIdentityStorage(args.identity)
    connection_storage = FileConnectionStorage(args.identity)

    client = RemoteAccessClient(args.proxy, identity_storage, connection_storage, event_handler=None)
    try:
        client.connect()

        if args.token:
            if looks_like_psk_token(args.token):
                client.pair_with_psk(args.token)
                print("Paired with PSK")
            else:
                fp = client.pair_with_handshake(args.token)
                print(f"Paired with rendezvous (fingerprint={fp})")
        elif args.session:
            client.load_existing_connection(args.session)
            print("Loaded cached connection")
        else:
            connections = connection_storage.list()
            if len(connections) == 1:
                client.load_existing_connection(connections[0].fingerprint)
                print(f"Auto-selected cached session: {connections[0].fingerprint[:16]}...")
            else:
                print(f"No token and {len(connections)} cached sessions — provide --token or --session")
                return 1

        print(f"Requesting '{args.domain}' — approve on listener...")
        cred = client.request_credential(args.domain)

        print(f"\n  Username: {cred.username}")
        print(f"  Password: {cred.password}")
        print(f"  TOTP:     {cred.totp}")
        print(f"  URI:      {cred.uri}")
        print(f"  Notes:    {cred.notes}")
    except (
        RemoteAccessError.ConnectionFailed,
        RemoteAccessError.HandshakeFailed,
        RemoteAccessError.CredentialRequestFailed,
        RemoteAccessError.SessionError,
        RemoteAccessError.InvalidArgument,
        RemoteAccessError.Timeout,
    ) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    finally:
        client.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
