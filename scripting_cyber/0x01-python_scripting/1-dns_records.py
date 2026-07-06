#!/usr/bin/env python3

import dns.resolver


def query_dns_records(domain_name):
    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain_name, record_type)
            records[record_type] = answers
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            return {}
        except dns.resolver.NoNameservers:
            continue

    return records
