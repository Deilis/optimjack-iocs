#!/usr/bin/env python3
"""Unpack the rule-engine build of track.js (08:01 UTC, 16 November 2026) without running it.

The file holds a JSON configuration. Each rule's code is a base64 string stored back to front:

    (new Function(atob("<reversed base64>".split("").reverse().join(""))))();

This script reads the configuration as JSON, reverses each string and decodes it. It evaluates nothing.

    python decode_rules.py track.js.txt
"""
import base64
import hashlib
import json
import re
import sys

source = open(sys.argv[1], encoding="utf-8", errors="replace").read()
start = re.search(r"var C\s*=\s*", source).end()
config, _ = json.JSONDecoder().raw_decode(source, start)
print("config version:", config.get("v"), "| geo endpoint:", config.get("g"), "| beacon endpoint:", config.get("p"))
for rule in config.get("r", []):
    wrapped = re.search(r'atob\("([A-Za-z0-9+/=]+)"\.split\(""\)\.reverse\(\)\.join\(""\)\)', rule.get("code", ""))
    if not wrapped:
        print("rule", rule.get("id"), rule.get("n"), "- no reversed base64 body")
        continue
    reversed_text = wrapped.group(1)[::-1]
    body = base64.b64decode(reversed_text + "=" * (-len(reversed_text) % 4))
    name = "rule-%s.js.txt" % rule.get("id")
    open(name, "wb").write(body)
    targeting = {key: rule[key] for key in rule if key not in ("code", "n", "id")}
    print("rule %s %r -> %s (%d bytes, sha256 %s) targeting %s" % (rule.get("id"), rule.get("n"), name, len(body), hashlib.sha256(body).hexdigest(), targeting))
