#!/usr/bin/env python3
# pcap_to_html.py — batch convert ./pcap/*.pcap → ./html/*.html
# No CSS, no JS, markup-only.

import os
import subprocess
import sys
import html
import xml.etree.ElementTree as ET

EM = "\u2003"  # indent

HTML_HEADER = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>{title}</title>
</head>
<body>
<h1>Packet Decode</h1>
"""

HTML_FOOTER = """
</body>
</html>
"""

DEFAULT_TSHARK_PATHS = [
    "tshark",
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]

def run_tshark_to_pdml(pcap_path: str) -> str:
    last_err = None
    for exe in DEFAULT_TSHARK_PATHS:
        try:
            out = subprocess.check_output(
                [exe, "-I", "-T", "pdml", "-r", pcap_path],
                stderr=subprocess.STDOUT
            )
            return out.decode("utf-8", errors="replace")
        except FileNotFoundError as e:
            last_err = e
            continue
        except subprocess.CalledProcessError as e:
            sys.stderr.write(e.output.decode("utf-8", errors="replace"))
            raise RuntimeError("tshark failed.") from e
    raise FileNotFoundError("Could not run tshark. Is Wireshark installed?") from last_err

def safe(s: str) -> str:
    return html.escape(s or "", quote=True)

def split_showname(sn: str) -> tuple[str, str]:
    # "Foo: Bar: Baz" -> ("Foo", "Bar: Baz") to keep everything
    if not sn:
        return "", ""
    left, sep, right = sn.partition(":")
    if not sep:
        return sn.strip(), ""
    return left.strip(), right.strip()

def field_label_and_value(n: ET.Element) -> tuple[str, str]:
    # Prefer splitting showname; then merge in attrs so nothing is lost.
    showname = n.get("showname") or ""
    left, right = split_showname(showname)

    # Base label/value
    label = left or n.get("name") or n.get("show") or "field"
    value_parts = []

    # Right side of showname (if any)
    if right:
        value_parts.append(right)

    # PDML attributes (only add if they add new info)
    attr_show = n.get("show")
    attr_value = n.get("value")
    # Avoid duplicate when right already equals attr_show
    for extra in (attr_show, attr_value):
        if extra and extra not in value_parts:
            value_parts.append(extra)

    return label, " | ".join(value_parts)

def render_field_rows(n: ET.Element, level: int, rows_out: list[str]) -> None:
    label, val = field_label_and_value(n)
    desc = (EM * level) + safe(label)
    rows_out.append(f"<tr><td>{desc}</td><td>{safe(val)}</td></tr>\n")
    for child in n.findall("field"):
        render_field_rows(child, level + 1, rows_out)

def proto_title(p: ET.Element) -> str:
    return p.get("showname") or p.get("name") or "proto"

def render_proto_block(proto: ET.Element) -> str:
    title = safe(proto_title(proto))
    rows = [f"<tr><td colspan='2'><b>{title}</b></td></tr>\n"]
    for f in proto.findall("field"):
        render_field_rows(f, 0, rows)
    nested_html = [render_proto_block(sp) for sp in proto.findall("proto")]
    table_html = "<table>\n" + "".join(rows) + "</table>\n"
    return f"<details><summary>{title}</summary>\n{table_html}{''.join(nested_html)}</details>\n"

def render_packet(pkt: ET.Element, idx: int) -> str:
    protos = [render_proto_block(p) for p in pkt.findall("proto")]
    return f"<h2>Packet {idx}</h2>\n<details><summary>Packet {idx} details</summary>\n{''.join(protos)}</details>\n"

def pdml_to_html(pdml_text: str, title: str) -> str:
    root = ET.fromstring(pdml_text)
    packets = root.findall(".//packet")
    parts = [HTML_HEADER.format(title=html.escape(title))]
    for i, pkt in enumerate(packets, start=1):
        parts.append(render_packet(pkt, i))
    parts.append(HTML_FOOTER)
    return "".join(parts)

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_dir = os.path.join(base_dir, "pcap")
    html_dir = os.path.join(base_dir, "html")
    os.makedirs(html_dir, exist_ok=True)

    pcaps = [f for f in os.listdir(pcap_dir) if f.lower().endswith(".pcap")]
    if not pcaps:
        sys.exit("No .pcap files found in ./pcap")

    for fname in pcaps:
        pcap_path = os.path.join(pcap_dir, fname)
        out_name = os.path.splitext(fname)[0] + ".html"
        out_path = os.path.join(html_dir, out_name)

        print(f"[+] Converting {fname} → {out_name}")
        pdml = run_tshark_to_pdml(pcap_path)
        html_out = pdml_to_html(pdml, f"{fname} — Decode")

        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_out)

    print("All pcaps converted.")

if __name__ == "__main__":
    main()
