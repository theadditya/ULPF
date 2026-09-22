"""
ULPF Declarative Parser Plugin Engine.
Provides zero-code, plug-and-play onboarding of new log sources using YAML specifications.
Supports dynamic loading, hot reloading, and zero data-loss field partitioning.
"""

from __future__ import annotations
import os
import re
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
from ulpf.parsing.extractors import (
    extract_syslog_header,
    parse_key_value,
    parse_cef,
    parse_leef,
    parse_json,
    parse_csv_line,
    parse_regex_pattern,
)
from ulpf.parsing.classifier import LogSourceClassifier


class ParserPlugin:
    """
    Encapsulates a declarative parser specification loaded from YAML.
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.id = config.get("id", "unknown_parser")
        self.name = config.get("name", "Unknown Parser")
        self.vendor = config.get("vendor", "Generic")
        self.product = config.get("product", "Perimeter Device")
        self.version = config.get("version", "1.0.0")
        self.format = config.get("format", "key_value")
        self.strip_syslog = config.get("strip_syslog_header", False)
        
        # Compiled regex if format is regex
        self.regex_pattern: Optional[re.Pattern] = None
        if self.format == "regex" and "pattern" in config.get("parser_config", {}):
            self.regex_pattern = re.compile(config["parser_config"]["pattern"])
            
        # CSV configuration
        self.csv_columns = config.get("parser_config", {}).get("columns", [])
        self.csv_delimiter = config.get("parser_config", {}).get("delimiter", ",")
        
        # Declarative Mappings & Value translations
        self.mapping = config.get("mapping", {})
        self.value_maps = config.get("value_maps", {})
        self.type_casts = config.get("type_casts", {})

    def extract_raw_fields(self, raw_line: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Executes format extraction according to the plugin configuration.
        Returns: (extracted_fields, syslog_metadata)
        """
        syslog_meta: Dict[str, Any] = {}
        payload = raw_line.strip()
        
        if self.strip_syslog or payload.startswith("<"):
            syslog_meta, payload = extract_syslog_header(payload)
            
        extracted: Dict[str, Any] = {}
        
        if self.format == "json":
            parsed_json = parse_json(payload)
            if parsed_json:
                extracted = parsed_json
        elif self.format == "cef":
            parsed_cef = parse_cef(raw_line)  # CEF needs full line for header
            if parsed_cef:
                extracted = parsed_cef
        elif self.format == "leef":
            parsed_leef = parse_leef(raw_line)
            if parsed_leef:
                extracted = parsed_leef
        elif self.format == "key_value":
            extracted = parse_key_value(payload)
        elif self.format == "csv":
            # Some CSV logs have a timestamp/hostname prefix before the CSV
            # If payload contains comma, find start of CSV
            parsed_csv = parse_csv_line(payload, self.csv_columns, self.csv_delimiter)
            if parsed_csv:
                extracted = parsed_csv
        elif self.format == "regex" and self.regex_pattern:
            parsed_regex = parse_regex_pattern(payload, self.regex_pattern)
            if parsed_regex:
                extracted = parsed_regex
        elif self.format == "syslog":
            # Just Syslog header + payload
            extracted = {"message": payload}
        else:
            # Fallback key-value
            extracted = parse_key_value(payload)

        # Merge syslog header meta into extracted fields
        if syslog_meta:
            extracted["_syslog_meta"] = syslog_meta
            
        return extracted, syslog_meta


class ParserRegistry:
    """
    Global registry managing declarative parser plugins.
    Supports directory scanning, hot-reloading, and auto-dispatch.
    """
    def __init__(self, configs_dir: Optional[str] = None):
        self.parsers: Dict[str, ParserPlugin] = {}
        self.configs_dir = configs_dir
        if configs_dir and os.path.exists(configs_dir):
            self.load_from_directory(configs_dir)

    def load_from_directory(self, dir_path: str):
        """Loads all .yaml and .yml files from the specified directory."""
        self.configs_dir = dir_path
        path = Path(dir_path)
        for yaml_file in path.glob("*.y*ml"):
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    config = yaml.safe_load(f)
                    if isinstance(config, dict) and "id" in config:
                        plugin = ParserPlugin(config)
                        self.parsers[plugin.id] = plugin
            except Exception as e:
                print(f"Warning: Failed to load parser config {yaml_file}: {e}")

    def register_plugin(self, plugin: ParserPlugin):
        self.parsers[plugin.id] = plugin

    def get_plugin(self, parser_id: str) -> Optional[ParserPlugin]:
        return self.parsers.get(parser_id)

    def parse(self, raw_line: str, parser_id: Optional[str] = None) -> Tuple[Dict[str, Any], ParserPlugin, float]:
        """
        Parses a raw log line. If parser_id is not specified, runs LogSourceClassifier
        to dynamically select the highest-confidence parser plugin.
        Returns: (extracted_fields, matched_plugin, confidence_score)
        """
        confidence = 1.0
        if not parser_id or parser_id not in self.parsers:
            detected_id, confidence = LogSourceClassifier.classify(raw_line)
            parser_id = detected_id

        plugin = self.parsers.get(parser_id)
        if not plugin:
            # Create a generic fallback plugin on the fly
            fallback_cfg = {
                "id": parser_id or "generic_fallback",
                "name": "Generic Fallback Parser",
                "vendor": "Generic",
                "product": "Perimeter Device",
                "format": "key_value",
                "strip_syslog_header": True,
            }
            plugin = ParserPlugin(fallback_cfg)

        extracted_fields, _ = plugin.extract_raw_fields(raw_line)
        return extracted_fields, plugin, confidence
