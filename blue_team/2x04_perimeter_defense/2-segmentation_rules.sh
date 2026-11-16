#!/bin/bash
# Emit a proposed IPv4 zone design. This script only writes a JSON data file.
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
    printf 'Missing required command: python3\n' >&2
    exit 1
fi

work_dir=$(mktemp -d "$PWD/.segmentation-rules.XXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT

python3 - "$work_dir/segmentation_rules.json" <<'PY'
import ipaddress
import itertools
import json
import sys

# Proposed design values, not addresses discovered on the current endpoint.
# Edit these together if the course supplies a different address plan.
PLAN = {
    "DMZ": {
        "cidr": "10.10.1.0/24",
        "purpose": "Public-facing application services",
    },
    "INTERNAL": {
        "cidr": "10.10.2.0/24",
        "purpose": "Clinical workstations, application servers, databases and PACS",
    },
    "MGMT": {
        "cidr": "10.10.3.0/24",
        "purpose": "Administration and the shared DNS resolver",
    },
    "MEDDEV": {
        "cidr": "10.10.4.0/24",
        "purpose": "Medical device VLAN with restricted outbound access",
    },
}
HOSTS = {
    "dmz-app-01": ("DMZ", "10.10.1.10", "application"),
    "dmz-app-02": ("DMZ", "10.10.1.11", "application"),
    "clinical-ws-01": ("INTERNAL", "10.10.2.101", "clinical_workstation"),
    "clinical-ws-02": ("INTERNAL", "10.10.2.102", "clinical_workstation"),
    "billing-srv-01": ("INTERNAL", "10.10.2.10", "database"),
    "ehr-srv-01": ("INTERNAL", "10.10.2.20", "clinical_application"),
    "pacs-srv-01": ("INTERNAL", "10.10.2.30", "pacs"),
    "mgmt-ws-01": ("MGMT", "10.10.3.10", "administrator"),
    "dns-resolver-01": ("MGMT", "10.10.3.53", "dns_resolver"),
    "med-device-01": ("MEDDEV", "10.10.4.10", "medical_device"),
    "med-device-02": ("MEDDEV", "10.10.4.11", "medical_device"),
}

networks = {name: ipaddress.ip_network(zone["cidr"]) for name, zone in PLAN.items()}
for first, second in itertools.combinations(networks.values(), 2):
    if first.overlaps(second):
        raise ValueError(f"Overlapping zone networks: {first} and {second}")
for name, (zone, address, _) in HOSTS.items():
    ip = ipaddress.ip_address(address)
    network = networks[zone]
    if ip not in network or ip in (network.network_address, network.broadcast_address):
        raise ValueError(f"Host {name} must have a usable address in {zone}")
if len({host[1] for host in HOSTS.values()}) != len(HOSTS):
    raise ValueError("Named host addresses must be unique")

flows = []


def selectors(zone, names):
    if names:
        if any(HOSTS[name][0] != zone for name in names):
            raise ValueError(f"A named host does not belong to {zone}")
        return [HOSTS[name][1] + "/32" for name in names]
    if zone == "ALL":
        return [item["cidr"] for item in PLAN.values()]
    return [PLAN[zone]["cidr"]]


def allow(src, dst, port, justification, proto="tcp", src_hosts=(), dst_hosts=()):
    flows.append({
        "id": f"A{len(flows) + 1:02d}",
        "action": "allow",
        "src_zone": src,
        "dst_zone": dst,
        "proto": proto,
        "dport": port,
        "src_hosts": list(src_hosts),
        "dst_hosts": list(dst_hosts),
        "src_cidrs": selectors(src, src_hosts),
        "dst_cidrs": selectors(dst, dst_hosts),
        "justification": justification,
        "exception_for": None,
    })


allow("MGMT", "INTERNAL", 22, "SSH administration from the management zone")
allow("MGMT", "DMZ", 22, "SSH administration from the management zone")
clinical_hosts = ("clinical-ws-01", "clinical-ws-02")
allow("INTERNAL", "INTERNAL", 443, "Clinical workstations access the EHR web service",
      src_hosts=clinical_hosts, dst_hosts=("ehr-srv-01",))
allow("INTERNAL", "INTERNAL", 3306, "Clinical workstations access the billing database",
      src_hosts=clinical_hosts, dst_hosts=("billing-srv-01",))
allow("DMZ", "INTERNAL", 3306, "Only the named DMZ application hosts may access the database",
      src_hosts=("dmz-app-01", "dmz-app-02"), dst_hosts=("billing-srv-01",))
allow("MEDDEV", "INTERNAL", 4242, "DICOM imaging to PACS", dst_hosts=("pacs-srv-01",))
allow("MEDDEV", "INTERNAL", 443, "EHR web integration for device display",
      dst_hosts=("ehr-srv-01",))
for protocol in ("udp", "tcp"):
    allow("ALL", "MGMT", 53, "Shared DNS resolution through the management resolver",
          proto=protocol, dst_hosts=("dns-resolver-01",))
allow("MGMT", "MEDDEV", 22, "Authorised SSH administration of medical devices")
allow("MGMT", "MEDDEV", 4242, "Authorised management access for DICOM diagnostics")

# Terminal rules follow the allow rules. They also make the unlisted ports and
# unnamed hosts in otherwise permitted pairs explicitly denied.
deny_number = 0


def deny_all(src, dst, destinations, justification):
    global deny_number
    deny_number += 1
    flows.append({
        "id": f"D{deny_number:02d}",
        "action": "deny_all",
        "src_zone": src,
        "dst_zone": dst,
        "proto": "all",
        "dport": None,
        "src_hosts": [],
        "dst_hosts": [],
        "src_cidrs": selectors(src, ()),
        "dst_cidrs": destinations,
        "justification": justification,
        "exception_for": None,
    })


for source, destination in itertools.product(PLAN, repeat=2):
    has_allow = any(
        flow["action"] == "allow"
        and flow["src_zone"] in (source, "ALL")
        and flow["dst_zone"] == destination
        for flow in flows
    )
    reason = (
        "Deny traffic not matched by the preceding explicit allow flows"
        if has_allow else "No allow flows are authorised for this zone pair"
    )
    deny_all(source, destination, [PLAN[destination]["cidr"]], reason)

# INTERNET means IPv4 destinations outside all four modelled zone networks.
# Expand the complement into CIDRs so both firewall backends can match the
# exact same address list without implementing different exclusion logic.
external_networks = [ipaddress.ip_network("0.0.0.0/0")]
for zone_network in networks.values():
    remaining = []
    for candidate in external_networks:
        if zone_network.subnet_of(candidate):
            remaining.extend(candidate.address_exclude(zone_network))
        else:
            remaining.append(candidate)
    external_networks = remaining
external_cidrs = [str(network) for network in sorted(
    external_networks, key=lambda item: (int(item.network_address), item.prefixlen)
)]
deny_all("MEDDEV", "INTERNET", external_cidrs,
         "Medical devices must not reach the public Internet or other external networks")

zones = []
for name, definition in PLAN.items():
    zones.append({
        "name": name,
        "cidr": definition["cidr"],
        "purpose": definition["purpose"],
        "default_inbound": "drop",
        "default_outbound": "accept",
        "outbound_restrictions": [
            flow["id"] for flow in flows
            if flow["src_zone"] == name and flow["action"] == "deny_all"
        ],
        "hosts": [
            {"name": hostname, "address": address, "role": role}
            for hostname, (zone, address, role) in HOSTS.items() if zone == name
        ],
    })

cross_pairs = list(itertools.permutations(PLAN, 2))
allowed_pairs = sum(any(
    flow["action"] == "allow" and flow["src_zone"] in (src, "ALL")
    and flow["dst_zone"] == dst for flow in flows
) for src, dst in cross_pairs)
document = {
    "zones": zones,
    "flows": flows,
    "summary": {
        "flow_count": len(flows),
        "allow_count": sum(flow["action"] == "allow" for flow in flows),
        "deny_count": sum(flow["action"] == "deny_all" for flow in flows),
        "cross_zone_pairs": len(cross_pairs),
        "allowed_cross_zone_pairs": allowed_pairs,
        "denied_cross_zone_pairs": len(cross_pairs) - allowed_pairs,
        "address_family": "ipv4",
        "address_plan": "Proposed design values; not discovered endpoint addresses",
        "evaluation_order": "First matching flow wins; terminal deny_all rules follow allows",
        "special_zones": {
            "ALL": list(PLAN),
            "INTERNET": "IPv4 addresses outside the four modelled zone CIDRs",
        },
    },
}
with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump(document, output, indent=2)
    output.write("\n")
print(
    f"Created segmentation_rules.json: {len(zones)} zones, "
    f"{document['summary']['allow_count']} allow flows, "
    f"{document['summary']['deny_count']} deny_all flows."
)
PY

mv -f -- "$work_dir/segmentation_rules.json" "$PWD/segmentation_rules.json"

