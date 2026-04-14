"""Threat intelligence data sources.

Each function queries a single intel backend and returns structured data.
In production, replace the mock databases with real API calls to:
- AbuseIPDB / GreyNoise / Shodan (IP reputation)
- VirusTotal / MalwareBazaar (file hashes)
- URLhaus / DomainTools / WHOIS (domains)
- MITRE ATT&CK STIX/TAXII (technique mapping)
"""

from __future__ import annotations

from alpha_ai.threat_intel.models import (
    DomainReputation,
    FileReputation,
    IPReputation,
    MitreMapping,
)

# ---------------------------------------------------------------------------
# Mock databases — swap with real API clients in production
# ---------------------------------------------------------------------------

_IP_DB: dict[str, dict] = {
    "203.0.113.42": {
        "ip": "203.0.113.42",
        "country": "Russia",
        "city": "Saint Petersburg",
        "asn": "AS48666",
        "isp": "MnogoByte LLC",
        "abuse_confidence_score": 87,
        "total_reports": 1243,
        "last_reported": "2026-03-10T14:22:00Z",
        "threat_types": ["botnet_c2", "malware_distribution", "brute_force"],
        "known_malware_associations": ["Emotet", "Trickbot"],
        "open_ports": [443, 8080, 4444],
        "is_tor_exit_node": False,
        "is_known_proxy": True,
        "first_seen": "2025-08-15T00:00:00Z",
        "tags": ["banking-trojan-c2", "spam-source"],
    },
    "198.51.100.23": {
        "ip": "198.51.100.23",
        "country": "China",
        "city": "Beijing",
        "asn": "AS4808",
        "isp": "CNCGROUP",
        "abuse_confidence_score": 92,
        "total_reports": 3421,
        "last_reported": "2026-04-01T09:15:00Z",
        "threat_types": ["apt_infrastructure", "scanning", "exploitation"],
        "known_malware_associations": ["PlugX", "ShadowPad"],
        "open_ports": [80, 443, 8443],
        "is_tor_exit_node": False,
        "is_known_proxy": False,
        "first_seen": "2024-11-20T00:00:00Z",
        "tags": ["apt41", "state-sponsored"],
    },
}

_HASH_DB: dict[str, dict] = {
    "d131dd02c5e6eec4693d9a0698aff95c": {
        "hash": "d131dd02c5e6eec4693d9a0698aff95c",
        "hash_type": "md5",
        "sha256": "a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01",
        "detections": 58,
        "total_engines": 72,
        "detection_rate": "80.6%",
        "malware_family": "Emotet",
        "malware_type": "banking_trojan",
        "severity": "critical",
        "file_type": "PE32 executable (DLL)",
        "file_size_bytes": 237568,
        "file_name": "update_service.dll",
        "first_seen": "2025-12-01T08:30:00Z",
        "last_seen": "2026-03-09T22:14:00Z",
        "tags": ["emotet", "epoch5", "banking-trojan", "dropper"],
        "behavior_summary": (
            "Drops secondary payload via regsvr32, establishes persistence "
            "via scheduled task, communicates with C2 over HTTPS on non-standard ports"
        ),
        "contacted_ips": ["203.0.113.42", "203.0.113.88", "192.0.2.101"],
        "contacted_domains": ["update-service-cdn.ru", "cdn-api-gateway.cc"],
    },
    "5d41402abc4b2a76b9719d911017c592": {
        "hash": "5d41402abc4b2a76b9719d911017c592",
        "hash_type": "md5",
        "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        "detections": 45,
        "total_engines": 72,
        "detection_rate": "62.5%",
        "malware_family": "Cobalt Strike",
        "malware_type": "beacon",
        "severity": "critical",
        "file_type": "PE32 executable",
        "file_size_bytes": 312320,
        "file_name": "svchost_update.exe",
        "first_seen": "2026-01-15T12:00:00Z",
        "last_seen": "2026-04-10T06:30:00Z",
        "tags": ["cobalt-strike", "beacon", "c2"],
        "behavior_summary": (
            "Cobalt Strike beacon with malleable C2 profile, "
            "injects into svchost.exe, uses named pipes for lateral movement"
        ),
        "contacted_ips": ["198.51.100.23"],
        "contacted_domains": ["cdn-update-service.cc"],
    },
}

_DOMAIN_DB: dict[str, dict] = {
    "secure-bankofamerica-login.com": {
        "domain": "secure-bankofamerica-login.com",
        "reputation_score": 98,
        "category": "phishing",
        "subcategory": "credential_harvesting",
        "active": True,
        "registrar": "NameSilo LLC",
        "registration_date": "2026-02-28T00:00:00Z",
        "registrant_country": "Panama",
        "hosting_provider": "BulletProof Hosting Ltd",
        "hosting_country": "Moldova",
        "ip_addresses": ["192.0.2.55", "192.0.2.56"],
        "mx_records": [],
        "ssl_issuer": "Let's Encrypt",
        "ssl_valid_from": "2026-02-28T00:00:00Z",
        "targeted_brand": "Bank of America",
        "similar_domains_found": 12,
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/2345678/",
        "tags": ["phishing-kit", "credential-harvest", "typosquat"],
        "associated_ips_with_other_malicious_domains": True,
        "dns_records": {
            "A": ["192.0.2.55"],
            "NS": ["ns1.bulletproof-dns.cc", "ns2.bulletproof-dns.cc"],
            "TXT": [],
        },
    },
    "update-service-cdn.ru": {
        "domain": "update-service-cdn.ru",
        "reputation_score": 95,
        "category": "malware_c2",
        "subcategory": "command_and_control",
        "active": True,
        "registrar": "REG.RU LLC",
        "registration_date": "2025-10-15T00:00:00Z",
        "registrant_country": "Russia",
        "hosting_provider": "DataLine LLC",
        "hosting_country": "Russia",
        "ip_addresses": ["203.0.113.42"],
        "tags": ["emotet-c2", "malware-distribution"],
        "associated_ips_with_other_malicious_domains": True,
        "dns_records": {"A": ["203.0.113.42"], "NS": ["ns1.reg.ru"], "TXT": []},
    },
}

_MITRE_DB: dict[str, dict] = {
    "command and control": {
        "techniques": [
            {
                "id": "T1071.001",
                "name": "Web Protocols",
                "tactic": "Command and Control",
                "description": "Adversaries communicate using application layer protocols associated with web traffic",
            },
            {
                "id": "T1573.002",
                "name": "Asymmetric Cryptography",
                "tactic": "Command and Control",
                "description": "Use asymmetric encryption for C2 communications",
            },
            {
                "id": "T1008",
                "name": "Fallback Channels",
                "tactic": "Command and Control",
                "description": "Use alternate communication channels if primary C2 is disrupted",
            },
        ],
        "associated_groups": ["APT28", "APT29", "Lazarus Group", "Wizard Spider"],
        "detection_suggestions": [
            "Monitor for unusual outbound HTTPS to non-standard ports",
            "Inspect TLS certificates for self-signed or recently issued certs",
            "Track beaconing patterns in network flow data",
        ],
    },
    "credential theft": {
        "techniques": [
            {
                "id": "T1056.001",
                "name": "Keylogging",
                "tactic": "Collection",
                "description": "Log keystrokes to intercept credentials as they are typed",
            },
            {
                "id": "T1555.003",
                "name": "Credentials from Web Browsers",
                "tactic": "Credential Access",
                "description": "Acquire credentials from web browser credential stores",
            },
            {
                "id": "T1003.001",
                "name": "LSASS Memory",
                "tactic": "Credential Access",
                "description": "Access credential material stored in LSASS process memory",
            },
        ],
        "associated_groups": ["Trickbot operators", "Emotet operators", "FIN7"],
        "detection_suggestions": [
            "Monitor for LSASS access by unusual processes",
            "Alert on credential store file access",
            "Deploy credential guard on endpoints",
        ],
    },
    "lateral movement": {
        "techniques": [
            {
                "id": "T1021.002",
                "name": "SMB/Windows Admin Shares",
                "tactic": "Lateral Movement",
                "description": "Use SMB admin shares for remote execution",
            },
            {
                "id": "T1550.002",
                "name": "Pass the Hash",
                "tactic": "Lateral Movement",
                "description": "Use stolen password hashes to authenticate without cracking",
            },
        ],
        "associated_groups": ["APT29", "FIN7", "Wizard Spider"],
        "detection_suggestions": [
            "Monitor for NTLM authentication anomalies",
            "Track SMB admin share access patterns",
            "Alert on unusual service creation on remote hosts",
        ],
    },
    "persistence": {
        "techniques": [
            {
                "id": "T1053.005",
                "name": "Scheduled Task",
                "tactic": "Persistence",
                "description": "Abuse scheduled tasks for persistence and execution",
            },
            {
                "id": "T1547.001",
                "name": "Registry Run Keys",
                "tactic": "Persistence",
                "description": "Use registry run keys for automatic execution at startup",
            },
        ],
        "associated_groups": ["Emotet operators", "APT41"],
        "detection_suggestions": [
            "Monitor scheduled task creation via Event ID 4698",
            "Track registry modifications to Run/RunOnce keys",
        ],
    },
    "phishing": {
        "techniques": [
            {
                "id": "T1566.001",
                "name": "Spearphishing Attachment",
                "tactic": "Initial Access",
                "description": "Send phishing emails with malicious attachments",
            },
            {
                "id": "T1566.002",
                "name": "Spearphishing Link",
                "tactic": "Initial Access",
                "description": "Send phishing emails with malicious links",
            },
        ],
        "associated_groups": ["APT28", "Lazarus Group", "FIN7"],
        "detection_suggestions": [
            "Implement email authentication (SPF, DKIM, DMARC)",
            "Train users on phishing recognition",
            "Deploy URL sandboxing for email links",
        ],
    },
}


def lookup_ip_reputation(ip_address: str) -> IPReputation:
    """Query IP reputation database."""
    data = _IP_DB.get(
        ip_address,
        {
            "ip": ip_address,
            "country": "Unknown",
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "threat_types": [],
            "note": "No records found for this IP",
        },
    )
    return IPReputation(**data)


def lookup_file_hash(file_hash: str, hash_type: str) -> FileReputation:
    """Query file reputation database."""
    data = _HASH_DB.get(
        file_hash,
        {
            "hash": file_hash,
            "hash_type": hash_type,
            "detections": 0,
            "total_engines": 72,
            "malware_family": "Unknown",
            "severity": "unknown",
            "note": "No records found for this hash",
        },
    )
    return FileReputation(**data)


def lookup_domain(domain: str) -> DomainReputation:
    """Query domain reputation database."""
    data = _DOMAIN_DB.get(
        domain,
        {
            "domain": domain,
            "reputation_score": 0,
            "category": "unknown",
            "active": None,
            "note": "No records found for this domain",
        },
    )
    return DomainReputation(**data)


def get_mitre_techniques(query: str) -> MitreMapping:
    """Map behaviors to MITRE ATT&CK techniques."""
    query_lower = query.lower()
    for key, mapping in _MITRE_DB.items():
        if key in query_lower:
            return MitreMapping(**mapping)
    return MitreMapping(note="No direct MITRE ATT&CK mapping found for this query.")
