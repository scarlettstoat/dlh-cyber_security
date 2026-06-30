#!/usr/bin/env python3
"""Resolve a domain name to an IPv4 address."""

import socket


def resolve_domain_to_ipv4(domain_name):
    """Return the IPv4 address for a domain name."""
    try:
        return socket.gethostbyname(domain_name)
    except socket.gaierror:
        return None
    except Exception as error:
        return str(error)
