import os
import lxml.etree as et
from subprocess import run, PIPE
import argparse
from html import escape

EM = "\u2003"
SKIP_PROTO_NAMES = {"fake-field-wrapper", "geninfo"}


def run_tshark_pdml(pcap_file, tshark_path):
    res = run([tshark_path, "-I", "-T", "pdml", "-r", pcap_file], stdout=PIPE, stderr=PIPE)
    if res.returncode != 0:
        raise RuntimeError(f"tshark error for {pcap_file}: {res.stderr.decode(errors='ignore')}")
    return et.fromstring(res.stdout)


def label(ele):
    showname = ele.get("showname")
    if showname:
        return showname
    name = ele.get("name") or ""
    show = ele.get("show")
    if show:
        return f"{name}: {show}"
    return name or "(unnamed)"


def get_frame_number(pkt):
    for proto in pkt:
        if proto.tag.endswith("proto") and proto.get("name") == "frame":
            for fld in proto:
                if fld.tag.endswith("field") and fld.get("name") == "frame.number":
                    return fld.get("show") or fld.get("value") or "?"
    return "?"


def render_field_rows(field_ele, depth, row_state):
    rows = []
    nm = field_ele.get("name") or ""
    if nm in SKIP_PROTO_NAMES:
        return rows  # skip whole block

    row_class = "even-tr" if row_state["toggle"] else "odd-tr"
    row_state["toggle"] = not row_state["toggle"]

    desc = escape(f"{EM * depth}{label(field_ele)}")
    rows.append(
        f'   <tr class="{row_class}">\n'
        f'      <td class="description">{desc}</td>\n'
        f'      <td class="space">&nbsp;</td>\n'
        f'      <td class="value"></td>\n'
        f'   </tr>\n'
    )

    for ch in field_ele:
        if ch.tag.endswith("field"):
            rows.extend(render_field_rows(ch, depth + 1, row_state))

    return rows


def render_proto(proto_ele, row_state):
    nm = proto_ele.get("name") or ""
    if nm in SKIP_PROTO_NAMES:
        return [] 

    rows = []
    if nm == "frame":
        rows.append(
            '   <tr class="frame">\n'
            f'      <td class="description"></td>\n'
            '      <td class="value"></td>\n'
            '   </tr>\n'
        )
        rows.append('   <tr><td class="space">&nbsp;</td></tr>\n')
        return rows

    proto_title = escape(label(proto_ele) or nm or "proto")
    rows.append(
        '   <tr class="frame">\n'
        f'      <td class="description">{proto_title}</td>\n'
        '      <td class="space">&nbsp;</td>\n'
        '      <td class="value"></td>\n'
        '   </tr>\n'
    )

    for ch in proto_ele:
        if ch.tag.endswith("field"):
            rows.extend(render_field_rows(ch, 1, row_state))

    rows.append('   <tr><td class="space">&nbsp;</td></tr>\n')
    return rows


def render_packet(pkt):
    frame_no = get_frame_number(pkt)

    rows = []
    rows.append(
        '   <tr class="frame">\n'
        f'      <td class="description">Frame {escape(frame_no)}</td>\n'
        '      <td class="space">&nbsp;</td>\n'
        '      <td class="value"></td>\n'
        '   </tr>\n'
    )

    row_state = {"toggle": True}
    for p in pkt:
        if p.tag.endswith("proto"):
            rows.extend(render_proto(p, row_state))

    return "<table class=\"decode\">\n" + "".join(rows) + "</table>\n"


def pdml_to_html(pdml_root, title):
    tables = [render_packet(pkt) for pkt in pdml_root if pkt.tag.endswith("packet")]
    return (
        "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n"
        f"<title>{escape(title)}</title>\n</head>\n<body>\n"
        + "".join(tables) +
        "</body>\n</html>\n"
    ).encode("utf-8")


def needs_update(pcap_path, html_path):
    if not os.path.exists(html_path):
        return True
    return os.path.getmtime(pcap_path) > os.path.getmtime(html_path)


def pcap_to_html(pcap_file_path, html_file_path):
    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
    pdml = run_tshark_pdml(pcap_file_path, tshark_path)
    title = os.path.basename(pcap_file_path)
    html_bytes = pdml_to_html(pdml, title)
    os.makedirs(os.path.dirname(html_file_path), exist_ok=True)
    with open(html_file_path, "wb") as f:
        f.write(html_bytes)
    print(f"HTML file created: {html_file_path}")


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
    parser = argparse.ArgumentParser(description="Batch convert PCAP files to <table class=decode> with even/odd rows")
    parser.add_argument("--pcap_dir", default="pcap", help="Directory containing PCAP files")
    parser.add_argument("--html_dir", default="HTML", help="Directory to save HTML files")
    args = parser.parse_args()
    main(args.pcap_dir, args.html_dir)
