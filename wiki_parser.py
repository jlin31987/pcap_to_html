#!/usr/bin/env python3
# pcap_to_html.py — batch convert ./pcap/*.pcap → ./html/*.html
# Markup-only (no JS, no CSS). Preserve ALL PDML content and order.

import os
import sys
import argparse
from subprocess import run, PIPE
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

# Attributes we don't duplicate in the bracket dump (structural/noise)
_ATTR_EXCLUDE = {
    "name", "showname", "show", "value", "pos", "size",
    "unmaskedvalue", "unmaskedshow", "unmaskedname",  # keep these unless empty
    "hide"
}

def _safe(s: str) -> str:
    return htmlesc.escape("" if s is None else str(s), quote=True)

def _split_showname(sn: str):
    # "Foo: Bar: Baz" => ("Foo", "Bar: Baz"). If no colon, value is empty.
    if not sn:
        return "", ""
    left, sep, right = sn.partition(":")
    if not sep:
        return sn.strip(), ""
    return left.strip(), right.strip()

def _field_label_value(n: et._Element):
    # Build the most complete label/value possible.
    sn = n.get("showname") or ""
    left, right = _split_showname(sn)
    label = left or n.get("name") or n.get("show") or "field"

    parts = []
    if right:
        parts.append(right)

    # Add show/value if present (keep even if duplicate; we want "everything")
    for k in ("show", "value", "unmaskedshow", "unmaskedvalue"):
        v = n.get(k)
        if v:
            parts.append(v)

    # Add pos/size if present
    for k in ("pos", "size"):
        v = n.get(k)
        if v:
            parts.append(f"{k}={v}")

    # Dump any remaining attributes so nothing is lost
    extras = []
    for k, v in n.items():
        if k in _ATTR_EXCLUDE:
            continue
        if v is None or v == "":
            continue
        extras.append(f"{k}={v}")
    if extras:
        parts.append("[" + ", ".join(extras) + "]")

    return label, " | ".join(parts)

def _render_field(n: et._Element, level: int, out_chunks: list):
    # Render this field
    label, val = _field_label_value(n)
    out_chunks.append(
        f"<tr><td>{EM * level}{_safe(label)}</td><td>{_safe(val)}</td></tr>\n"
    )
    # Recurse into children, preserving order
    for child in n:
        if child.tag == "field":
            _render_field(child, level + 1, out_chunks)
        elif child.tag == "proto":
            _render_proto(child, level + 1, out_chunks)

def _proto_title(p: et._Element) -> str:
    return p.get("showname") or p.get("name") or "proto"

def _render_proto(p: et._Element, level: int, out_chunks: list):
    title = _safe(_proto_title(p))
    rows = [f"<tr><td colspan='2'><b>{title}</b></td></tr>\n"]

    # Collect body rows in original order
    body_chunks = []
    for child in p:
        if child.tag == "field":
            _render_field(child, 0, body_chunks)
        elif child.tag == "proto":
            # nested proto: render into its own <details>
            nested_chunks = []
            _render_proto(child, 0, nested_chunks)
            body_chunks.append("".join(nested_chunks))

    table_html = "<table>\n" + "".join(rows) + "".join(body_chunks) + "</table>\n"
    out_chunks.append(f"<details><summary>{title}</summary>\n{table_html}</details>\n")

def _render_packet(pkt: et._Element, idx: int, out_chunks: list):
    out_chunks.append(f"<h2>Packet {idx}</h2>\n")
    inner = []
    # Preserve proto order exactly as in PDML
    for p in pkt.findall("proto"):
        _render_proto(p, 0, inner)
    out_chunks.append(
        f"<details><summary>Packet {idx} details</summary>\n{''.join(inner)}</details>\n"
    )

def pdml_to_html(dom: et._Element, title: str) -> bytes:
    packets = dom.findall(".//packet")
    parts = [HTML_HEADER.format(title=_safe(title))]
    for i, pkt in enumerate(packets, start=1):
        _render_packet(pkt, i, parts)
    parts.append(HTML_FOOTER)
    return "".join(parts).encode("utf-8")

# ---------- pipeline identical shape to your XSLT script ----------

def pcap_to_html(pcap_file_path: str, html_file_path: str) -> None:
    if os.path.exists(html_file_path):
        print(f"HTML file already exists: {html_file_path}. Skipping creation.")
        return

    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"

    result = run(
        [tshark_path, "-I", "-T", "pdml", "-r", pcap_file_path],
        stdout=PIPE,
        stderr=PIPE
    )
    if result.returncode != 0:
        print(f"Error running tshark on {pcap_file_path}:", result.stderr.decode(errors="replace"))
        return

    try:
        dom = et.fromstring(result.stdout)
    except et.XMLSyntaxError as e:
        print(f"PDML parse error for {pcap_file_path}: {e}")
        return

    html_bytes = pdml_to_html(dom, os.path.basename(pcap_file_path))
    os.makedirs(os.path.dirname(html_file_path), exist_ok=True)
    with open(html_file_path, "wb") as f:
        f.write(html_bytes)
    print(f"HTML file created: {html_file_path}")

def needs_update(pcap_path: str, html_path: str) -> bool:
    if not os.path.exists(html_path):
        return True
    return os.path.getmtime(pcap_path) > os.path.getmtime(html_path)

def main(pcap_folder: str, html_folder: str) -> None:
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
