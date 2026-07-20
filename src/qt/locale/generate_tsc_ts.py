#!/usr/bin/env python3
"""Generate Qt .ts translation files from _tsc_strings.json and a translations JSON.

Usage:
    python3 generate_tsc_ts.py <lang_code> <translations.json> [--output <path>]

The translations JSON must have the same structure as _tsc_strings.json:
    { "ContextName": ["translated string 1", "translated string 2", ...], ... }

If a translation is empty string "", it will be marked type="unfinished".
"""

import json
import sys
import os
from xml.sax.saxutils import escape


def generate_ts(lang_code: str, sources: dict, translations: dict, output_path: str):
    lines = []
    lines.append('<?xml version="1.0" encoding="utf-8"?>')
    lines.append("<!DOCTYPE TS>")
    lines.append(f'<TS version="2.1" language="{lang_code}">')

    for context_name, source_strings in sources.items():
        trans_strings = translations.get(context_name, [])
        lines.append("<context>")
        lines.append(f"    <name>{escape(context_name)}</name>")

        for i, source in enumerate(source_strings):
            translation = trans_strings[i] if i < len(trans_strings) else ""
            lines.append("    <message>")
            lines.append(f"        <source>{escape(source)}</source>")
            if translation:
                lines.append(f'        <translation type="unfinished">{escape(translation)}</translation>')
            else:
                lines.append('        <translation type="unfinished"></translation>')
            lines.append("    </message>")

        lines.append("</context>")

    lines.append("</TS>")
    lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Generated {output_path} ({len(sources)} contexts)")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate Qt .ts file from translations JSON")
    parser.add_argument("lang_code", help="Language code (e.g., es, fr, de)")
    parser.add_argument("translations_json", help="Path to translations JSON file")
    parser.add_argument("--output", "-o", help="Output .ts file path")
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    sources_path = os.path.join(script_dir, "_tsc_strings.json")

    with open(sources_path, "r", encoding="utf-8") as f:
        sources = json.load(f)

    with open(args.translations_json, "r", encoding="utf-8") as f:
        translations = json.load(f)

    output = args.output or os.path.join(script_dir, f"tsc_{args.lang_code}.ts")
    generate_ts(args.lang_code, sources, translations, output)


if __name__ == "__main__":
    main()
