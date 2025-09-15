# pcap_to_html.py — PDML -> zero-JS, markup-only HTML in Kayla's decode table style
import os
import re
import argparse
from subprocess import run, PIPE
from typing import List, Tuple
import lxml.etree as et

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
EM = "\u2003"  # U+2003 em space for indent
SKIP_PROTOS = {"fake-field-wrapper"}  # do not render this wrapper
HTML_TITLE_RE = re.compile(br"<title>.*?</title>", re.DOTALL)

def run_tshark_pdml(pcap_path: str) -> bytes:
    """Return PDML bytes from tshark."""
    result = run([TSHARK, "-I", "-T", "pdml", "-r", pcap_path], stdout=PIPE, stderr=PIPE)
    if result.returncode != 0:
        raise RuntimeError(f"tshark error on {pcap_path}:\n{result.stderr.decode(errors='replace')}")
    return result.stdout

def split_showname(showname: str) -> Tuple[str, str]:
    """
    Split a Wireshark 'showname' like 'Frame Length: 92 bytes (736 bits)'
    into ('Frame Length', '92 bytes (736 bits)').
    If no colon, treat whole thing as description.
    """
    if not showname:
        return "", ""
    parts = showname.split(": ", 1)
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip()
    return showname.strip(), ""

def row_html(tr_class: str, desc: str, value: str) -> str:
    return (
        f'   <tr class="{tr_class}">\n'
        f'      <td class="description">{desc}</td>\n'
        f'      <td class="space">&nbsp;</td>\n'
        f'      <td class="value">{value}</td>\n'
        f'   </tr>\n'
    )

def spacer_row() -> str:
    return '   <tr><td class="space">&nbsp;</td></tr>\n'

def html_esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def collect_fields_rows(node, depth: int, rows: List[str], next_is_even: List[bool]) -> None:
    """
    Depth-first over <field> nodes, rendering Wireshark-style key/value rows.
    depth controls EM-space indentation of the 'description' cell.
    next_is_even is a one-item list used as a mutable toggle for even/odd classes.
    """
    showname = node.get("showname") or node.get("name") or ""
    desc, value = split_showname(showname)
    # Fallbacks: if value empty, try 'show' or 'value' attrs
    if not value:
        value = node.get("show") or node.get("value") or ""

    # Indent description with EM spaces
    indented_desc = (EM * depth) + html_esc(desc)
    tr_class = "even-tr" if next_is_even[0] else "odd-tr"
    next_is_even[0] = not next_is_even[0]

    rows.append(row_html(tr_class, indented_desc, html_esc(value)))

    # Recurse into child fields
    for child in node.findall("field"):
        collect_fields_rows(child, depth + 1, rows, next_is_even)

def packet_table_html(packet, title_anchor: str) -> str:
    """
    Build one <table class="decode"> for a packet.
    Within the table, each protocol gets a <tr class="frame"> header, then its fields.
    """
    # Protocol list for the frame summary line
    protos = [p.get("name") for p in packet.findall("proto") if p.get("name") not in SKIP_PROTOS]
    frame_line = f'⇒ Frame {packet.get("showname", "") or ""}: ' + ", ".join(protos)

    rows: List[str] = []
    next_is_even = [True]  # toggle holder

    # Emit a header + fields per proto
    for proto in packet.findall("proto"):
        pname = proto.get("name") or ""
        if pname in SKIP_PROTOS:
            continue

        # Section header
        rows.append(
            '   <tr class="frame">\n'
            f'      <td class="description">{html_esc(pname)}</td>\n'
            '      <td class="space">&nbsp;</td>\n'
            '      <td class="value"></td>\n'
            '   </tr>\n'
        )

        # Fields inside this proto
        for field in proto.findall("field"):
            collect_fields_rows(field, depth=1, rows=rows, next_is_even=next_is_even)

        # Spacer between protos
        rows.append(spacer_row())

    # Wrap with table
    table = []
    table.append('<table class="decode">\n')
    # Optional: top summary line as its own header block
    table.append(
        '   <tr class="frame">\n'
        f'      <td class="description">{html_esc(frame_line)}</td>\n'
        '      <td class="space">&nbsp;</td>\n'
        '      <td class="value"></td>\n'
        '   </tr>\n'
    )
    table.append(spacer_row())
    table.extend(rows)
    table.append('</table>\n')

    # Prepend a section <h2> with anchor
    h2 = f'<h2><a class="title_anchor" name="{html_esc(title_anchor)}"></a>{html_esc(title_anchor)}<br></h2>\n'
    return h2 + "".join(table)

def pdml_to_markup_html(pdml_bytes: bytes, page_title: str) -> bytes:
    """Convert PDML to your markup-only HTML page."""
    dom = et.fromstring(pdml_bytes)
    packets = dom.findall(".//packet")

    body_parts: List[str] = []
    for idx, pkt in enumerate(packets, start=1):
        # Example anchor/title per packet
        anchor = f"decode_{idx}"
        body_parts.append(packet_table_html(pkt, anchor))

    # Minimal HTML skeleton (no CSS/JS; only classes)
    html = (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "  <head>\n"
        f"    <title>{html_esc(page_title)}</title>\n"
        "    <meta charset=\"utf-8\"/>\n"
        "  </head>\n"
        "  <body>\n"
        + "".join(body_parts) +
        "  </body>\n"
        "</html>\n"
    )
    return html.encode("utf-8")

def pcap_to_html(pcap_file_path: str, html_file_path: str) -> None:
    """PCAP -> PDML -> markup-only HTML."""
    pdml = run_tshark_pdml(pcap_file_path)
    html_bytes = pdml_to_markup_html(pdml, os.path.basename(pcap_file_path))
    os.makedirs(os.path.dirname(html_file_path), exist_ok=True)
    with open(html_file_path, "wb") as f:
        f.write(html_bytes)
    print(f"HTML file created: {html_file_path}")

def needs_update(pcap_path: str, html_path: str) -> bool:
    """True if HTML missing or older than PCAP."""
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
    parser = argparse.ArgumentParser(description="Batch convert PCAP files to markup-only HTML (no JS/XSLT)")
    parser.add_argument("--pcap_dir", default="pcap", help="Directory containing PCAP files")
    parser.add_argument("--html_dir", default="HTML", help="Directory to save HTML files")
    args = parser.parse_args()
    main(args.pcap_dir, args.html_dir)
