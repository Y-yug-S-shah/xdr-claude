import os
import re
import math
import json
import sqlite3
import requests
from datetime import datetime, timedelta
from collections import Counter

CORTEX_API_URL = os.getenv("CORTEX_API_URL", "https://api.cortex.example.com")
CORTEX_API_KEY = os.getenv("CORTEX_API_KEY")
CORTEX_API_KEY_ID = os.getenv("CORTEX_API_KEY_ID")
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

DB_FILE = "triage_cache.db"

IOC_REGEXS = {
    "SHA256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "MD5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "SHA1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "URL": re.compile(r"\bhttps?://[^\s\"'<>\)\]]+"),
    "Domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
    "IPv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "IPv6": re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"),
    "Email": re.compile(
      
