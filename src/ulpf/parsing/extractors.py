"""
ULPF Log Extractors.
High-performance extractors for Syslog (RFC 3164 / 5424), Key-Value, CEF, LEEF,
CSV/TSV, JSON, and Regex patterns.
"""

from __future__ import annotations
import re
import csv
import json
import io
from typing import Dict, Any, Optional, Tuple, List


# Regex for RFC 3164 / 5424 PRI header e.g. <134> or <14>
SYSLOG_PRI_REGEX = re.compile(r"^<(\d{1,3})>(.*)$")

# Regex for key-value pairs handling both quoted strings and unquoted tokens
# e.g., key="some value" or key='some value' or key=val
KV_REGEX = re.compile(r'([a-zA-Z0-9_\.\-]+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s,]+))')

# Regex for CEF: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
CEF_HEADER_REGEX = re.compile(
    r"^(?:<(?:\d+)>)?\s*(?:[A-Za-z]{3}\s+\d+\s+[\d:]+\s+\S+\s+)?CEF:\s*(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$"
)

# Regex for LEEF: LEEF:Version|Vendor|Product|Version|EventID|Extension (or with delimiter)
LEEF_HEADER_REGEX = re.compile(
    r"^(?:<(?:\d+)>)?\s*(?:[A-Za-z]{3}\s+\d+\s+[\d:]+\s+\S+\s+)?LEEF:\s*([\d\.]+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(?:(0x[0-9a-fA-F]+|[^\w|])\|)?(.*)$"
)


def extract_syslog_header(line: str) -> Tuple[Dict[str, Any], str]:
    """
    Extracts RFC PRI header and returns metadata dict + remainder message.
    PRI = Facility * 8 + Severity.
    """
    meta: Dict[str, Any] = {}
    cleaned = line.strip()
    match = SYSLOG_PRI_REGEX.match(cleaned)
    if match:
        pri = int(match.group(1))
        facility = pri >> 3
        severity = pri & 7
        meta["syslog_pri"] = pri
        meta["syslog_facility"] = facility
        meta["syslog_severity"] = severity
        cleaned = match.group(2).strip()
    return meta, cleaned


def parse_key_value(text: str) -> Dict[str, Any]:
    """
    Extracts key-value pairs from strings like:
    date=2026-09-22 time=18:00:00 devname="FGT-EDGE" type="traffic" action="accept" sentbyte=1200
    """
    result: Dict[str, Any] = {}
    for match in KV_REGEX.finditer(text):
        key = match.group(1)
        val = match.group(2) or match.group(3) or match.group(4)
        result[key] = val
    return result


def parse_cef(line: str) -> Optional[Dict[str, Any]]:
    """
    Parses ArcSight Common Event Format (CEF).
    """
    match = CEF_HEADER_REGEX.search(line)
    if not match:
        return None
        
    version, vendor, product, dev_version, event_class_id, name, severity, ext = match.groups()
    result = {
        "cef_version": version,
        "device_vendor": vendor.strip(),
        "device_product": product.strip(),
        "device_version": dev_version.strip(),
        "device_event_class_id": event_class_id.strip(),
        "event_name": name.strip(),
        "severity": severity.strip(),
    }
    
    # Parse extension key-value pairs
    ext_dict = parse_key_value(ext)
    result.update(ext_dict)
    return result


def parse_leef(line: str) -> Optional[Dict[str, Any]]:
    """
    Parses Log Event Extended Format (LEEF).
    """
    match = LEEF_HEADER_REGEX.search(line)
    if not match:
        return None
        
    version, vendor, product, dev_version, event_id, custom_delim, ext = match.groups()
    result = {
        "leef_version": version,
        "device_vendor": vendor.strip(),
        "device_product": product.strip(),
        "device_version": dev_version.strip(),
        "event_id": event_id.strip(),
    }
    
    # Determine delimiter (default tab or custom)
    delim = custom_delim if custom_delim else "\t"
    if delim.startswith("0x"):
        try:
            delim = chr(int(delim, 16))
        except ValueError:
            delim = "\t"

    # Split extension
    parts = ext.split(delim) if delim in ext else [ext]
    for part in parts:
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip()] = v.strip()
            
    # Also attempt standard kv regex if few items matched
    if len(result) <= 5:
        kv_extra = parse_key_value(ext)
        result.update(kv_extra)
        
    return result


def flatten_dict(d: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
    """Recursively flattens nested dictionaries into dot-separated keys."""
    items: List[Tuple[str, Any]] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def parse_json(line: str) -> Optional[Dict[str, Any]]:
    """Attempts to parse JSON payload (e.g. Suricata EVE JSON or Zeek JSON) and flattens nested objects."""
    trimmed = line.strip()
    if not (trimmed.startswith("{") and trimmed.endswith("}")):
        # Look for embedded JSON within a syslog header
        first_brace = trimmed.find("{")
        last_brace = trimmed.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            trimmed = trimmed[first_brace:last_brace + 1]
        else:
            return None
    try:
        data = json.loads(trimmed)
        if isinstance(data, dict):
            flat = flatten_dict(data)
            # Also keep top-level keys
            flat.update({k: v for k, v in data.items() if not isinstance(v, dict)})
            return flat
    except Exception:
        pass
    return None


def parse_csv_line(line: str, column_names: List[str], delimiter: str = ",") -> Optional[Dict[str, Any]]:
    """
    Parses delimited row into named columns.
    Handles embedded quotes and commas correctly.
    """
    try:
        reader = csv.reader(io.StringIO(line.strip()), delimiter=delimiter)
        for row in reader:
            if not row:
                return None
            res: Dict[str, Any] = {}
            for i, col in enumerate(column_names):
                if i < len(row):
                    res[col] = row[i].strip()
                else:
                    res[col] = None
            # Store any extra columns beyond predefined column_names
            if len(row) > len(column_names):
                for idx in range(len(column_names), len(row)):
                    res[f"extra_col_{idx}"] = row[idx].strip()
            return res
    except Exception:
        return None
    return None


def parse_regex_pattern(text: str, pattern: re.Pattern) -> Optional[Dict[str, Any]]:
    """Applies compiled regex pattern with named capture groups."""
    match = pattern.search(text)
    if match:
        return match.groupdict()
    return None
