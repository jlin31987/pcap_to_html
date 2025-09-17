import os
import lxml.etree as et
from subprocess import run, PIPE
import argparse

EM_SPACE = "\u2003"     
NBSP = "\u00A0"         
INDENT_MODE = "nbsp"   
NBSP_PER_LEVEL = 4      

SKIP_PROTO_NAMES = {"fake-field-wrapper", "geninfo"}

def make_indent(depth: int) -> str:
    if depth <= 0:
        return ""
    if INDENT_MODE == "emsp":
        return EM_SPACE * depth
    if INDENT_MODE == "emsp_nbsp":
        return (EM_SPACE + NBSP) * depth
    return NBSP * (NBSP_PER_LEVEL * depth)

def run_tshark_pdml(pcap_file_path, tshark_path=r"C:\Program Files\Wireshark\tshark.exe") -> et._Element:
    result = run([tshark_path, "-I", "-T", "pdml", "-r", pcap_file_path], stdout=PIPE, stderr=PIPE)
    if result.returncode != 0:
        raise RuntimeError(f"tshark failed on {pcap_file_path}:\n{result.stderr.decode(errors='ignore')}")
    return et.fromstring(result.stdout)

def pdml_to_plain_html(pdml_root: et._Element, pcap_basename: str) -> et._Element:
    html = et.Element("html")
    head = et.SubElement(html, "head")
    et.SubElement(head, "meta", charset="utf-8")
    title = et.SubElement(head, "title"); title.text = pcap_basename
    body = et.SubElement(html, "body")

    packets = pdml_root.findall(".//packet")
    for idx, pkt in enumerate(packets, start=1):
        proto_names = []
        for p in pkt.findall("./proto"):
            name = p.get("name")
            if name and name not in SKIP_PROTO_NAMES:
                proto_names.append(name)
        frame_title = f"Frame {idx}" + (": " + ", ".join(proto_names) if proto_names else "")

        h2 = et.SubElement(body, "h2")
        et.SubElement(h2, "a", attrib={"class": "title_anchor", "name": f"decode_{idx}"}).tail = frame_title
        et.SubElement(h2, "br")

        table = et.SubElement(body, "table", attrib={"class": "decode"})

        for proto in pkt.findall("./proto"):
            name = proto.get("name")
            if not name or name in SKIP_PROTO_NAMES:
                continue

            tr = et.SubElement(table, "tr", attrib={"class": "frame"})
            et.SubElement(tr, "td", attrib={"class": "description"}).text = proto.get("showname") or name or "protocol"
            et.SubElement(tr, "td", attrib={"class": "space"}).text = "\u00A0"
            et.SubElement(tr, "td", attrib={"class": "value"}).text = ""

            row_i = 0
            row_classes = ("even-tr", "odd-tr")

            def add_field_row(desc_text: str, value_text: str, depth: int):
                nonlocal row_i
                trf = et.SubElement(table, "tr", attrib={"class": row_classes[row_i % 2]})
                row_i += 1
                dcell = et.SubElement(trf, "td", attrib={"class": "description"})
                dcell.text = f"{make_indent(depth)}{desc_text}"
                et.SubElement(trf, "td", attrib={"class": "space"}).text = "\u00A0"
                et.SubElement(trf, "td", attrib={"class": "value"}).text = value_text

            def emit_fields(elem: et._Element, depth: int):
                for fld in elem.findall("./field"):
                    showname = (fld.get("showname") or fld.get("name") or "")
                    value = fld.get("show") or fld.get("value") or ""
                    desc = showname
                    if not value and ":" in showname:
                        left, right = showname.split(":", 1)
                        # keep LHS spacing except trailing; don't nuke potential inner spaces
                        desc, value = left.rstrip(), right.strip()
                    add_field_row(desc, value, depth)

                    if fld.find("./field") is not None or fld.find("./proto") is not None:
                        emit_fields(fld, depth + 1)

                for subp in elem.findall("./proto"):
                    subn = subp.get("name")
                    if not subn or subn in SKIP_PROTO_NAMES:
                        continue
                    trn = et.SubElement(table, "tr", attrib={"class": "frame"})
                    et.SubElement(trn, "td", attrib={"class": "description"}).text = subp.get("showname") or subn or "protocol"
                    et.SubElement(trn, "td", attrib={"class": "space"}).text = "\u00A0"
                    et.SubElement(trn, "td", attrib={"class": "value"}).text = ""
                    emit_fields(subp, depth + 1)

            emit_fields(proto, depth=0)

            spacer = et.SubElement(table, "tr")
            et.SubElement(spacer, "td", attrib={"class": "space"}).text = "\u00A0"

    return html

def pcap_to_html(pcap_file_path, html_file_path):
    pdml_root = run_tshark_pdml(pcap_file_path)
    html_root = pdml_to_plain_html(pdml_root, os.path.basename(pcap_file_path))
    os.makedirs(os.path.dirname(html_file_path), exist_ok=True)
    html_bytes = et.tostring(html_root, pretty_print=True, method="html")
    with open(html_file_path, "wb") as f:
        f.write(html_bytes)
    print(f"HTML file created: {html_file_path}")

def needs_update(pcap_path, html_path):
    return not os.path.exists(html_path) or os.path.getmtime(pcap_path) > os.path.getmtime(html_path)

def main(pcap_folder, html_folder):
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
    parser = argparse.ArgumentParser(description="Batch convert PCAP files to HTML (no JS/CSS).")
    parser.add_argument("--pcap_dir", default="pcap", help="Directory containing PCAP files")
    parser.add_argument("--html_dir", default="HTML", help="Directory to save HTML files")
    args = parser.parse_args()
    main(args.pcap_dir, args.html_dir)
