#!/usr/bin/env python3
"""redteam.py: authorized red team simulator for a website YOU own.

Simulates external attacks against your own target, reports every finding
with an exact fix. Non-destructive by construction: scope gate, request
budget, gentle rate limit, benign payloads only, no brute force, no DoS.

  python3 redteam.py --target https://example.com --allow example.com --i-own-this
"""

import argparse
import base64
import difflib
import gzip
import hashlib
import hmac
import html as htmllib
import ipaddress
import json
import os
import random
import threading
import re
import secrets
import socket
import ssl
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from html.parser import HTMLParser

import http.client

VERSION = "1.1.0"
UA = "placeholder_websiteRedTeamBot/1.0 (authorized self-testing)"
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {"CRITICAL": "#ff2d55", "HIGH": "#ff6b35", "MEDIUM": "#ffb020",
             "LOW": "#4aa3ff", "INFO": "#7d8590"}

# OWASP Top 10:2025, verified at https://top10.owasp.org/2025/en/
OWASP = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}
OWASP_URL = {
    "A01": "https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/",
    "A02": "https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/",
    "A03": "https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/",
    "A04": "https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/",
    "A05": "https://top10.owasp.org/2025/A05_2025-Injection/",
    "A06": "https://top10.owasp.org/2025/A06_2025-Insecure_Design/",
    "A07": "https://top10.owasp.org/2025/A07_2025-Authentication_Failures/",
    "A08": "https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/",
    "A09": "https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/",
    "A10": "https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
}
CHEATSHEET = "https://cheatsheetseries.owasp.org/cheatsheets/"

SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|private[_-]?key"
    r"|auth|credential|dsn|connection[_-]?string)\b\s*[:=]\s*[^\s;,&\"']+")
