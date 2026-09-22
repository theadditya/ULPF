"""
ULPF Network Classification and Offline Enrichment.
Fully operational in air-gapped environments without internet access.
Handles RFC 1918, Bogon, direction detection, port categorization, and offline GeoIP/ASN mapping.
"""

from __future__ import annotations
import ipaddress
from typing import Tuple, Optional
from ulpf.core.models import NetworkDirection, EndpointInfo


# Offline demonstration GeoIP / ASN table for typical public enterprise ranges
OFFLINE_GEO_ASN_TABLE = [
    (ipaddress.ip_network("8.8.8.0/24"), "US", "Mountain View", "AS15169 Google LLC"),
    (ipaddress.ip_network("1.1.1.0/24"), "AU", "Sydney", "AS13335 Cloudflare Inc"),
    (ipaddress.ip_network("104.16.0.0/12"), "US", "San Francisco", "AS13335 Cloudflare Inc"),
    (ipaddress.ip_network("185.220.101.0/24"), "DE", "Frankfurt", "AS205100 Tor Exit Relay"),
    (ipaddress.ip_network("45.33.32.0/24"), "US", "Fremont", "AS63949 Linode LLC"),
    (ipaddress.ip_network("198.51.100.0/24"), "US", "Reston", "AS12345 Documentation Range"),
    (ipaddress.ip_network("203.0.113.0/24"), "IN", "Mumbai", "AS55836 Reliance Jio"),
    (ipaddress.ip_network("52.0.0.0/11"), "US", "Ashburn", "AS16509 Amazon.com Inc"),
    (ipaddress.ip_network("13.107.0.0/16"), "US", "Redmond", "AS8075 Microsoft Corp"),
    (ipaddress.ip_network("194.26.29.0/24"), "RU", "Moscow", "AS57523 Suspicious Scanner Range"),
]


RFC_1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def is_private_or_internal(ip_str: Optional[str]) -> bool:
    """Returns True if the IP address is strictly RFC 1918, loopback, or link-local."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return any(ip in net for net in RFC_1918_NETWORKS)
    except ValueError:
        return False


def get_offline_geo_asn(ip_str: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Offline GeoIP & ASN resolver.
    Matches against local subnet trie without making network queries.
    Returns: (country, city, asn)
    """
    if not ip_str:
        return None, None, None
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if ip.is_private:
            return "INTERNAL", "LAN", "Private Network (RFC 1918)"
        
        for net, country, city, asn in OFFLINE_GEO_ASN_TABLE:
            if ip in net:
                return country, city, asn
        
        # Default fallback for unlisted public IPs in air-gapped mode
        return "GLOBAL", "External", "Public Internet"
    except ValueError:
        return None, None, None


def determine_direction(src_ip: Optional[str], dst_ip: Optional[str]) -> NetworkDirection:
    """
    Determines network direction (Inbound, Outbound, Lateral, etc.)
    based on RFC 1918 perimeter boundaries.
    """
    if not src_ip or not dst_ip:
        return NetworkDirection.UNKNOWN
    
    src_internal = is_private_or_internal(src_ip)
    dst_internal = is_private_or_internal(dst_ip)
    
    if src_internal and dst_internal:
        return NetworkDirection.LATERAL
    elif src_internal and not dst_internal:
        return NetworkDirection.OUTBOUND
    elif not src_internal and dst_internal:
        return NetworkDirection.INBOUND
    else:
        return NetworkDirection.EXTERNAL


import socket

def resolve_live_dns(ip_str: Optional[str], timeout_sec: float = 0.35) -> Optional[str]:
    """
    Resolves reverse DNS (PTR) hostname for public IPs in Public Web Cloud Mode.
    Strictly bypassed in Air-Gapped mode to prevent DNS exfiltration/leakage.
    """
    if not ip_str:
        return None
    try:
        socket.setdefaulttimeout(timeout_sec)
        host, _, _ = socket.gethostbyaddr(ip_str.strip())
        return host
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None


def enrich_endpoints(src: EndpointInfo, dst: EndpointInfo, deployment_mode: str = "air_gapped") -> NetworkDirection:
    """
    Mutates and populates endpoint internal status, GeoIP, ASN, and hostname data.
    In Air-Gapped mode: strictly zero outbound network sockets or DNS queries are executed.
    In Public Web Cloud mode: executes non-blocking reverse DNS (PTR) for public IPs.
    Returns determined network direction.
    """
    if src.ip:
        src.is_internal = is_private_or_internal(src.ip)
        country, city, asn = get_offline_geo_asn(src.ip)
        if not src.country:
            src.country = country
        if not src.city:
            src.city = city
        if not src.asn:
            src.asn = asn
        if deployment_mode == "internet" and not src.is_internal and not src.hostname:
            src.hostname = resolve_live_dns(src.ip)
            
    if dst.ip:
        dst.is_internal = is_private_or_internal(dst.ip)
        country, city, asn = get_offline_geo_asn(dst.ip)
        if not dst.country:
            dst.country = country
        if not dst.city:
            dst.city = city
        if not dst.asn:
            dst.asn = asn
        if deployment_mode == "internet" and not dst.is_internal and not dst.hostname:
            dst.hostname = resolve_live_dns(dst.ip)

    return determine_direction(src.ip, dst.ip)
