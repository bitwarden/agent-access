#!/usr/bin/env python3
"""Interactive test script for UniFFI Python bindings.

Usage:
    python test.py --token <PSK_TOKEN> --domain github.com
"""

import argparse
import sys
sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))

from ap_uniffi import (
    RemoteAccessClient,
    RemoteAccessError,
    looks_like_psk_token,
)
from storage import MemoryConnectionStorage, MemoryIdentityStorage

PROXY = "wss://ap.lesspassword.dev"


def main():
    parser = argparse.ArgumentParser(description="Test UniFFI Python bindings")
    parser.add_argument("--token", required=True, help="PSK token or rendezvous code")
    parser.add_argument("--domain", default="github.com", help="Domain to request")
    parser.add_argument("--proxy", default=PROXY, help="Proxy URL")
    args = parser.parse_args()

    client = RemoteAccessClient(
        args.proxy,
        MemoryIdentityStorage(),
        MemoryConnectionStorage(),
        event_handler=None,
    )
    try:
        client.connect()

        if looks_like_psk_token(args.token):
            client.pair_with_psk(args.token)
            print("Paired with PSK")
        else:
            fp = client.pair_with_handshake(args.token)
            print(f"Paired with rendezvous (fingerprint={fp})")

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
