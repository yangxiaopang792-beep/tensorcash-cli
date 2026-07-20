#!/usr/bin/env python3
"""Apply a partial translations JSON to a _tsc_translations_<lang>.json file.

Usage: python3 apply_translations.py <lang> <partial_translations.json>

The partial translations JSON should have format:
{"ContextName": {"index": "translated string", ...}, ...}
"""
import json, sys, os

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <lang> <partial_translations.json>")
    sys.exit(1)

lang = sys.argv[1]
partial_path = sys.argv[2]

script_dir = os.path.dirname(os.path.abspath(__file__))
trans_path = os.path.join(script_dir, f"_tsc_translations_{lang}.json")

with open(trans_path) as f:
    trans = json.load(f)
with open(partial_path) as f:
    partial = json.load(f)

applied = 0
for ctx, entries in partial.items():
    if ctx not in trans:
        continue
    for idx_str, translated in entries.items():
        idx = int(idx_str)
        if idx < len(trans[ctx]) and translated:
            trans[ctx][idx] = translated
            applied += 1

with open(trans_path, 'w', encoding='utf-8') as f:
    json.dump(trans, f, ensure_ascii=False, indent=2)

print(f"{lang}: applied {applied} translations")
