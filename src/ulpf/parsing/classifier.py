"""
ULPF Log Source Classifier & Heuristic Detector.
Automatically identifies vendor, format, and appropriate parser for any log string
without requiring prior manual labeling.
"""

from __future__ import annotations
import re
from typing import Tuple, Optional, Dict, Any


class LogSourceClassifier:
    """
    High-speed heuristic classifier for perimeter network device logs.
    """

    # Signatures for zero-shot detection
    SIG_CEF = re.compile(r"CEF:\s*\d+\|")
    SIG_LEEF = re.compile(r"LEEF:\s*[\d\.]+\|")
    SIG_CISCO_ASA = re.compile(r"%ASA-\d+-\d+:")
    SIG_CISCO_FTD = re.compile(r"%FTD-\d+-\d+:")
    SIG_CISCO_IOS = re.compile(r"%(?:SEC_LOGIN|[A-Z0-9_]+)-\d+-[A-Z0-9_]+:")
    SIG_FORTINET = re.compile(r'(?:devname=|logid=|type=["\']?traffic["\']?|subtype=["\']?forward["\']?)')
    SIG_SURICATA = re.compile(r'"event_type"\s*:\s*"(?:alert|flow|dns|http|tls|netflow)"')
    SIG_PFSENSE = re.compile(r"(?:filterlog(?::|\[\d+\]:)?\s*\d+,\d+,|,\d+,[a-zA-Z0-9_-]+,match,)")
    SIG_SNORT = re.compile(r"\[\*\*\]\s*\[\d+:\d+:\d+\]")
    SIG_ZEEK = re.compile(r"(?:^#separator\s+|^\d+\.\d+\t\w+\t[\d\.]+\t\d+\t[\d\.]+\t\d+)")

    @classmethod
    def classify(cls, line: str) -> Tuple[str, float]:
        """
        Classifies incoming log line and returns (parser_id, confidence_score).
        """
        raw = line.strip()
        if not raw:
            return "generic_raw", 0.0

        # 1. CEF
        if cls.SIG_CEF.search(raw):
            return "generic_cef", 0.98

        # 2. LEEF
        if cls.SIG_LEEF.search(raw):
            return "generic_leef", 0.98

        # 3. Cisco ASA / FTD / IOS
        if cls.SIG_CISCO_ASA.search(raw):
            return "cisco_asa", 0.99
        if cls.SIG_CISCO_FTD.search(raw):
            return "cisco_asa", 0.95
        if cls.SIG_CISCO_IOS.search(raw):
            return "cisco_ios", 0.95

        # 4. Suricata EVE JSON
        if raw.startswith("{") or '"event_type"' in raw:
            if cls.SIG_SURICATA.search(raw):
                return "suricata_eve", 0.99
            if '"src_ip"' in raw and '"dest_ip"' in raw:
                return "generic_json", 0.85

        # 5. Fortinet FortiOS (Key-Value)
        if cls.SIG_FORTINET.search(raw):
            return "fortinet_fortios", 0.95

        # 6. pfSense filterlog
        if cls.SIG_PFSENSE.search(raw) or "filterlog:" in raw or "filterlog[" in raw:
            return "pfsense_filterlog", 0.95

        # 7. Snort Fast Alert
        if cls.SIG_SNORT.search(raw):
            return "snort_fast", 0.95

        # 8. Zeek TSV
        if cls.SIG_ZEEK.search(raw) or ("\t" in raw and raw.count("\t") >= 8):
            return "zeek_conn", 0.90

        # 9. Palo Alto PAN-OS CSV / Syslog
        # PAN-OS traffic syslog typically has: "1,2026/09/22 18:00:00,001801000001,TRAFFIC," or contains ",TRAFFIC," / ",THREAT,"
        if ",TRAFFIC," in raw or ",THREAT," in raw or ",SYSTEM," in raw:
            return "palo_alto_traffic", 0.95
        if raw.count(",") >= 15 and re.search(r"\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}", raw):
            return "palo_alto_traffic", 0.90

        # 10. Check if generic key-value
        if raw.count("=") >= 4 and (" " in raw or "," in raw):
            return "generic_kv", 0.80

        # 11. Generic Syslog RFC 3164/5424
        if raw.startswith("<") and ">" in raw[:5]:
            return "generic_syslog", 0.75

        return "generic_raw", 0.50
