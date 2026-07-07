#!/usr/bin/env python3
"""Check if a port is open."""

import socket


def check_port(host, port):
    """Check a TCP Port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


if __name__ == "__main__":
    pass
