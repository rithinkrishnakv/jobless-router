"""
Automated mitigation playbook -- advisory text generation only.

Jobless-Router deliberately never opens a live BGP session or pushes
config to a real router. A false positive in *automated* mitigation can
black-hole legitimate traffic faster than the original hijack would have
-- that failure mode is itself a recurring cause of real outages. Every
function here returns human-reviewable text for an operator to read,
sanity-check, and apply themselves (or wire into your own change-controlled
automation with an explicit approval gate).
"""


def generate_rtbh_text(prefix: str) -> str:
    return (
        f"# RTBH (Remote Triggered Black Hole) suggestion for {prefix}\n"
        f"# Tag a trigger route to {prefix} with your upstream's documented blackhole\n"
        f"# community (RFC 7999 default: 65535:666) and announce it over your existing\n"
        f"# blackhole-trigger BGP session, so upstream routers drop traffic to this\n"
        f"# prefix at their edge instead of yours.\n"
        f"# Advisory only -- review and announce manually."
    )


def generate_flowspec_rule(prefix: str) -> str:
    safe_name = prefix.replace("/", "_").replace(".", "_")
    return (
        "# Example BGP Flowspec rule (RFC 8955), ExaBGP-style syntax.\n"
        "# Review before injecting into any real session.\n"
        "flow {\n"
        f"    route discard_{safe_name} {{\n"
        "        match {\n"
        f"            destination {prefix};\n"
        "        }\n"
        "        then {\n"
        "            discard;\n"
        "        }\n"
        "    }\n"
        "}"
    )


def generate_vendor_acl(prefix: str, rogue_asn: int, vendor: str = "cisco") -> str:
    vendor = vendor.lower()
    if vendor == "cisco":
        return (
            f"! Cisco IOS/IOS-XR -- deny routes for {prefix}\n"
            f"ip prefix-list BLOCK-{rogue_asn} deny {prefix}\n"
            f"route-map FILTER-AS{rogue_asn} deny 10\n"
            f" match ip address prefix-list BLOCK-{rogue_asn}\n"
            f"route-map FILTER-AS{rogue_asn} permit 20"
        )
    if vendor == "juniper":
        return (
            f"/* Juniper JunOS -- deny routes for {prefix} */\n"
            "policy-options {\n"
            f"    prefix-list block-{rogue_asn} {{ {prefix}; }}\n"
            f"    policy-statement filter-as{rogue_asn} {{\n"
            "        term deny-leak {\n"
            f"            from {{ prefix-list block-{rogue_asn}; }}\n"
            "            then reject;\n"
            "        }\n"
            "        term default-accept { then accept; }\n"
            "    }\n"
            "}"
        )
    if vendor == "arista":
        return (
            f"! Arista EOS -- deny routes for {prefix}\n"
            f"ip prefix-list BLOCK-{rogue_asn} seq 10 deny {prefix}\n"
            f"route-map FILTER-AS{rogue_asn} deny 10\n"
            f" match ip address prefix-list BLOCK-{rogue_asn}"
        )
    return f"# Unknown vendor '{vendor}' -- supported: cisco, juniper, arista"


def build_playbook(prefix: str, rogue_asn: int) -> str:
    parts = [
        generate_rtbh_text(prefix),
        "",
        generate_flowspec_rule(prefix),
        "",
        generate_vendor_acl(prefix, rogue_asn, "cisco"),
    ]
    return "\n".join(parts)
