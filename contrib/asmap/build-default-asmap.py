#!/usr/bin/env python3
# Copyright (c) 2026-present The TensorCash developers
# Distributed under the MIT software license.
"""Reproducibly (re)build the bundled default ip_asn.map shipped in the binary.

Source: iptoasn.com — Public Domain, PDDL v1.0 (per iptoasn.com), derived from
RouteViews; freely redistributable, so it is safe to embed in a distributed binary.
(MaxMind GeoLite2 is NOT — its EULA restricts redistribution. Do not switch to it.)

Pipeline: iptoasn TSV -> range->CIDR text -> contrib/asmap/asmap-tool.py encode -> ip_asn.map

Run from anywhere:  python3 contrib/asmap/build-default-asmap.py
Writes ip_asn.map next to this script and prints the artifact size + sha256 + coverage.
Regenerate at each release (or monthly); IP->ASN is stable for months.
"""
import datetime
import gzip
import hashlib
import ipaddress
import json
import os
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "asmap-tool.py")
OUT_MAP = os.path.join(HERE, "ip_asn.map")
OUT_TXT = os.path.join(HERE, "ip_asn.txt")  # transient intermediate
ASN_MAX = 33521664  # _CODER_ASN max in asmap.py (_VarLenCoder(1, range(15,25))); above = private/reserved 32-bit
SOURCES = {
    "v4": "https://iptoasn.com/data/ip2asn-v4.tsv.gz",
    "v6": "https://iptoasn.com/data/ip2asn-v6.tsv.gz",
}
CLOUD_ASNS = {  # coverage sanity — where cheap sybil capacity actually lives
    16509: "AWS", 14618: "AWS", 15169: "GCP", 396982: "GCP-cloud", 8075: "Azure",
    24940: "Hetzner", 16276: "OVH", 14061: "DigitalOcean", 13335: "Cloudflare", 20473: "Vultr",
}


def fetch(url):
    print(f"  fetching {url}", file=sys.stderr)
    req = urllib.request.Request(url, headers={"User-Agent": "asmap-builder"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return gzip.decompress(r.read())


def main():
    n_rows = n_lines = n_skipped = 0
    asn_present = set()
    input_meta = {}
    with open(OUT_TXT, "w") as out:
        for _fam, url in SOURCES.items():
            data = fetch(url)
            input_meta[url] = {"decompressed_sha256": hashlib.sha256(data).hexdigest(),
                               "decompressed_bytes": len(data)}
            for line in data.decode("utf-8", "replace").splitlines():
                if not line.strip():
                    continue
                f = line.split("\t")  # start \t end \t ASN \t country \t desc
                if len(f) < 3:
                    continue
                n_rows += 1
                try:
                    asn = int(f[2])
                except ValueError:
                    continue
                if asn == 0 or asn > ASN_MAX:  # unannounced or private/reserved -> leave unmapped
                    n_skipped += 1
                    continue
                try:
                    a, b = ipaddress.ip_address(f[0]), ipaddress.ip_address(f[1])
                    for net in ipaddress.summarize_address_range(a, b):
                        out.write(f"{net} AS{asn}\n")
                        n_lines += 1
                    asn_present.add(asn)
                except ValueError:
                    continue

    print(f"rows={n_rows} cidrs={n_lines} skipped={n_skipped} asns={len(asn_present)}", file=sys.stderr)
    with open(OUT_MAP, "wb") as mo:
        subprocess.run([sys.executable, TOOL, "encode", OUT_TXT], stdout=mo, check=True)
    os.remove(OUT_TXT)

    data = open(OUT_MAP, "rb").read()
    art_sha = hashlib.sha256(data).hexdigest()
    print(f"wrote {OUT_MAP}: {len(data)/1e6:.2f} MB  sha256={art_sha}", file=sys.stderr)

    # Record the exact source snapshot so the artifact is auditable, not just rebuildable.
    manifest = {
        "artifact": "ip_asn.map",
        "artifact_sha256": art_sha,
        "artifact_bytes": len(data),
        "built_utc_date": datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
        "builder": "contrib/asmap/build-default-asmap.py",
        "encoder": "contrib/asmap/asmap-tool.py encode",
        "source": "iptoasn.com (Public Domain, PDDL v1.0; RouteViews-derived)",
        "inputs": input_meta,
        "filter": f"dropped AS0 (unannounced) and ASN > {ASN_MAX} (asmap _CODER_ASN max; private/reserved 32-bit)",
        "reproducibility": ("Rebuildable any time, but bit-identical reproduction of THIS artifact requires the "
                            "same iptoasn snapshot (regenerated daily). The input decompressed_sha256 values pin "
                            "the exact inputs so drift is detectable."),
    }
    with open(OUT_MAP + ".manifest", "w") as mf:
        json.dump(manifest, mf, indent=2, sort_keys=True)
        mf.write("\n")
    print(f"wrote {OUT_MAP}.manifest", file=sys.stderr)

    missing = [f"{a}({n})" for a, n in CLOUD_ASNS.items() if a not in asn_present]
    print(f"cloud-ASN coverage: {len(CLOUD_ASNS) - len(missing)}/{len(CLOUD_ASNS)}"
          + (f"  MISSING={missing}" if missing else "  (all present)"), file=sys.stderr)


if __name__ == "__main__":
    main()
