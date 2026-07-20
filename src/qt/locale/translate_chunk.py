#!/usr/bin/env python3
"""Split _tsc_strings.json into per-context chunk files for translation.

Usage:
    python3 translate_chunk.py split <lang>       # creates chunks/_chunk_<lang>_<ctx>.json
    python3 translate_chunk.py merge <lang>       # merges chunks into _tsc_translations_<lang>.json
    python3 translate_chunk.py generate <lang>    # runs generate_tsc_ts.py to produce .ts file
"""

import json, os, sys, subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(SCRIPT_DIR, "_tsc_strings.json")
CHUNKS_DIR = os.path.join(SCRIPT_DIR, "chunks")


def split(lang):
    os.makedirs(CHUNKS_DIR, exist_ok=True)
    with open(SOURCE) as f:
        data = json.load(f)
    for ctx, strings in data.items():
        chunk_path = os.path.join(CHUNKS_DIR, f"_chunk_{lang}_{ctx}.json")
        if os.path.exists(chunk_path):
            print(f"  SKIP (exists): {chunk_path}")
            continue
        # Write source strings as placeholder - agent will overwrite with translations
        with open(chunk_path, "w", encoding="utf-8") as cf:
            json.dump({ctx: strings}, cf, ensure_ascii=False, indent=2)
        print(f"  Created: {chunk_path} ({len(strings)} strings)")
    print(f"\nSplit into {len(data)} chunk files in {CHUNKS_DIR}/")


def merge(lang):
    with open(SOURCE) as f:
        source = json.load(f)
    merged = {}
    missing = []
    for ctx in source:
        chunk_path = os.path.join(CHUNKS_DIR, f"_chunk_{lang}_{ctx}.json")
        if os.path.exists(chunk_path):
            with open(chunk_path, encoding="utf-8") as cf:
                chunk = json.load(cf)
            merged[ctx] = chunk.get(ctx, source[ctx])
            if len(merged[ctx]) != len(source[ctx]):
                print(f"  WARNING: {ctx} has {len(merged[ctx])} strings, expected {len(source[ctx])}")
        else:
            missing.append(ctx)
            merged[ctx] = source[ctx]  # fallback to English

    out_path = os.path.join(SCRIPT_DIR, f"_tsc_translations_{lang}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)
    print(f"Merged {len(merged)} contexts into {out_path}")
    if missing:
        print(f"  Missing chunks (English fallback): {missing}")


def generate(lang):
    trans_path = os.path.join(SCRIPT_DIR, f"_tsc_translations_{lang}.json")
    gen_script = os.path.join(SCRIPT_DIR, "generate_tsc_ts.py")
    subprocess.run(["python3", gen_script, lang, trans_path], check=True)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    cmd, lang = sys.argv[1], sys.argv[2]
    if cmd == "split":
        split(lang)
    elif cmd == "merge":
        merge(lang)
    elif cmd == "generate":
        generate(lang)
    else:
        print(f"Unknown command: {cmd}")
