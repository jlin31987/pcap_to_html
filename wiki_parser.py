#!/usr/bin/env python3
# pcap_to_html.py — batch convert ./pcap/*.pcap → ./html/*.html
# Markup-only output (no JS, no CSS). lxml + Python transform, XSLT-free.

import os
import re
import sys
from subprocess import run, PIPE
import argparse
import html as htmlesc
import lxml.etree as et

EM = "\u2003"  # Wireshark-like indent

HTML_HEADER = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>{title}</title>
</head>
<body>
<h1>Packet Decode</h1>
"""

HTML_FOOTER = """
</body>
</html>
"""

# ---------- PDML → Markup-only HTML (Python "transform") ----------

def _safe(s: str) -> str:
    return htmlesc.escape(s or "", quote=True)

def _split_showname(sn: str) -> tuple[str, str]:
    # "Foo: Bar: Baz" -> ("Foo", "Bar: Baz")
    if not sn:
        return "", ""
    left, sep, right = sn.partition(":")
    return (sn.strip(), "") if not sep else (left.strip(), right.strip())

def _label_value_from_field(n: et._Element) -> tuple[str, str]:
    # Prefer showname split; then add PDML attrs if they add info.
    showname = n.get("showname") or ""
    left, right = _split_showname(showname)
    label = left or n.get("name") or n.get("show") or "field"

    value_parts = []
    if right:
        value_parts.append(right)

    # Merge attributes without duplicates
    for extra in (n.get("show"), n.get("value")):
        if extra and extra not in value_parts:
            value_parts.append(extra)

    return label, " | ".join(value_parts)

def _render_field_rows(n: et._Element, level: int, out_rows: list[str]) -> None:
    label, val = _label_value_from_field(n)
    desc = (EM * level) + _safe(label)
    out_rows.append(f"<tr><td>{desc}</td><td>{_safe(val)}</td></tr>\n")
    for child in n.findall("field"):
        _render_field_rows(child, level + 1, out_rows)

def _proto_title(p: et._Element) -> str:
    return p.get("showname") or p.get("name") or "proto"

def _render_proto(proto: et._Element) -> str:
    title = _safe(_proto_title(proto))
    rows = [f"<tr><td colspan='2'><b>{title}</b></td></tr>\n"]
    for f in proto.findall("field"):
        _render_field_rows(f, 0, rows)
    nested = "".join(_render_proto(sp) for sp in proto.findall("proto"))
    table_html = "<table>\n" + "".join(rows) + "</table>\n"
    return f"<details><summary>{title}</summary>\n{table_html}{nested}</details>\n"

def pdml_to_html_markup_only(dom: et._Element, title: str) -> bytes:
    packets = dom.findall(".//packet")
    parts = [HTML_HEADER.format(title=_safe(title))]
    for i, pkt in enumerate(packets, start=1):
        protos = "".join(_render_proto(p) for p in pkt.findall("proto"))
        parts.append(
            f"<h2>Packet {i}</h2>\n"
            f"<details><summary>Packet {i} details</summary>\n{protos}</details>\n"
        )
    parts.append(HTML_FOOTER)
    return "".join(parts).encode("utf-8")

# ---------- I/O pipeline (same logic/shape as your XSLT script) ----------

def pcap_to_html(pcap_file_path: str, html_file_path: str) -> None:
    """
    Converts a PCAP file to an HTML file (markup-only).
    """
    # If HTML already exists, skip (same behavior)
    if os.path.exists(html_file_path):
        print(f"HTML file already exists: {html_file_path}. Skipping creation.")
        return

    # Full path to tshark executable (default install path on Windows)
    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"

    # Run tshark and capture PDML
    result = run(
        [tshark_path, "-I", "-T", "pdml", "-r", pcap_file_path],
        stdout=PIPE,
        stderr=PIPE
    )
    if result.returncode != 0:
        print(f"Error running tshark on {pcap_file_path}:", result.stderr.decode(errors="replace"))
        return

    # Parse PDML
    try:
        dom = et.fromstring(result.stdout)
    except et.XMLSyntaxError as e:
        print(f"PDML parse error for {pcap_file_path}: {e}")
        return

    # Transform PDML → HTML (markup-only, no JS/CSS)
    html_bytes = pdml_to_html_markup_only(dom, os.path.basename(pcap_file_path))

    # Ensure output dir exists
    os.makedirs(os.path.dirname(html_file_path), exist_ok=True)

    # Write HTML
    with open(html_file_path, "wb") as f:
        f.write(html_bytes)

    print(f"HTML file created: {html_file_path}")

def needs_update(pcap_path: str, html_path: str) -> bool:
    """
    Return True if HTML doesn't exist or PCAP is newer.
    """
    if not os.path.exists(html_path):
        return True
    return os.path.getmtime(pcap_path) > os.path.getmtime(html_path)

def main(pcap_folder: str, html_folder: str) -> None:
    """
    Scan PCAP folder, convert to HTML in html_folder,
    only if HTML is missing or out-of-date.
    """
    os.makedirs(html_folder, exist_ok=True)

    for filename in os.listdir(pcap_folder):
        if filename.lower().endswith(".pcap"):
            pcap_path = os.path.join(pcap_folder, filename)
            html_filename = os.path.splitext(filename)[0] + ".html"
            html_path = os.path.join(html_folder, html_filename)

            if needs_update(pcap_path, html_path):
                print(f"Processing: {pcap_path}")
                pcap_to_html(pcap_path, html_path)
            else:
                print(f"Up-to-date HTML exists for {filename}, skipping.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Batch convert PCAP files to HTML (markup-only)")
    parser.add_argument("--pcap_dir", default="pcap", help="Directory containing PCAP files")
    parser.add_argument("--html_dir", default="html", help="Directory to save HTML files")
    args = parser.parse_args()
    main(args.pcap_dir, args.html_dir)
