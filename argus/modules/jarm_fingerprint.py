#!/usr/bin/env python3
"""Argus - JARM TLS Fingerprint.

JARM is an active TLS server fingerprint: ten specially crafted Client Hello
packets are sent, and the server's choice of cipher, TLS version and extensions
across all ten responses is condensed into a 62-character hash. Two servers with
the same TLS stack and configuration share a JARM, which makes it a cheap way to
group infrastructure and to match a host against known-malware C2 fingerprints.

This is a faithful, self-contained port of Salesforce's JARM algorithm
(github.com/salesforce/jarm). The packet construction, cipher/ALPN/version
tables and fuzzy-hash are byte-for-byte compatible with the reference, so the
hashes this module emits can be looked up directly against public JARM datasets.
"""
import os, sys, json, io, socket, hashlib, time
from struct import pack
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from argus.utils.util import clean_domain_input, ensure_directory_exists
from argus.config.settings import EXPORT_SETTINGS, RESULTS_DIR

console = Console()
TEAL = "#2EC4B6"

# --- exact reference tables -------------------------------------------------
ALL_CIPHERS = [
    b"\x00\x16", b"\x00\x33", b"\x00\x67", b"\xc0\x9e", b"\xc0\xa2", b"\x00\x9e",
    b"\x00\x39", b"\x00\x6b", b"\xc0\x9f", b"\xc0\xa3", b"\x00\x9f", b"\x00\x45",
    b"\x00\xbe", b"\x00\x88", b"\x00\xc4", b"\x00\x9a", b"\xc0\x08", b"\xc0\x09",
    b"\xc0\x23", b"\xc0\xac", b"\xc0\xae", b"\xc0\x2b", b"\xc0\x0a", b"\xc0\x24",
    b"\xc0\xad", b"\xc0\xaf", b"\xc0\x2c", b"\xc0\x72", b"\xc0\x73", b"\xcc\xa9",
    b"\x13\x02", b"\x13\x01", b"\xcc\x14", b"\xc0\x07", b"\xc0\x12", b"\xc0\x13",
    b"\xc0\x27", b"\xc0\x2f", b"\xc0\x14", b"\xc0\x28", b"\xc0\x30", b"\xc0\x60",
    b"\xc0\x61", b"\xc0\x76", b"\xc0\x77", b"\xcc\xa8", b"\x13\x05", b"\x13\x04",
    b"\x13\x03", b"\xcc\x13", b"\xc0\x11", b"\x00\x0a", b"\x00\x2f", b"\x00\x3c",
    b"\xc0\x9c", b"\xc0\xa0", b"\x00\x9c", b"\x00\x35", b"\x00\x3d", b"\xc0\x9d",
    b"\xc0\xa1", b"\x00\x9d", b"\x00\x41", b"\x00\xba", b"\x00\x84", b"\x00\xc0",
    b"\x00\x07", b"\x00\x04", b"\x00\x05",
]
NO13_CIPHERS = [
    b"\x00\x16", b"\x00\x33", b"\x00\x67", b"\xc0\x9e", b"\xc0\xa2", b"\x00\x9e",
    b"\x00\x39", b"\x00\x6b", b"\xc0\x9f", b"\xc0\xa3", b"\x00\x9f", b"\x00\x45",
    b"\x00\xbe", b"\x00\x88", b"\x00\xc4", b"\x00\x9a", b"\xc0\x08", b"\xc0\x09",
    b"\xc0\x23", b"\xc0\xac", b"\xc0\xae", b"\xc0\x2b", b"\xc0\x0a", b"\xc0\x24",
    b"\xc0\xad", b"\xc0\xaf", b"\xc0\x2c", b"\xc0\x72", b"\xc0\x73", b"\xcc\xa9",
    b"\xcc\x14", b"\xc0\x07", b"\xc0\x12", b"\xc0\x13", b"\xc0\x27", b"\xc0\x2f",
    b"\xc0\x14", b"\xc0\x28", b"\xc0\x30", b"\xc0\x60", b"\xc0\x61", b"\xc0\x76",
    b"\xc0\x77", b"\xcc\xa8", b"\xcc\x13", b"\xc0\x11", b"\x00\x0a", b"\x00\x2f",
    b"\x00\x3c", b"\xc0\x9c", b"\xc0\xa0", b"\x00\x9c", b"\x00\x35", b"\x00\x3d",
    b"\xc0\x9d", b"\xc0\xa1", b"\x00\x9d", b"\x00\x41", b"\x00\xba", b"\x00\x84",
    b"\x00\xc0", b"\x00\x07", b"\x00\x04", b"\x00\x05",
]
# ALPN ALL list preserves the reference's implicit-concatenation quirk on the
# spdy/3 + h2 entry - the JARM hash depends on these exact bytes.
ALPN_ALL = [
    b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39", b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30",
    b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x31", b"\x06\x73\x70\x64\x79\x2f\x31",
    b"\x06\x73\x70\x64\x79\x2f\x32", b"\x06\x73\x70\x64\x79\x2f\x33\x02\x68\x32",
    b"\x03\x68\x32\x63", b"\x02\x68\x71",
]
ALPN_RARE = [
    b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39", b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30",
    b"\x06\x73\x70\x64\x79\x2f\x31", b"\x06\x73\x70\x64\x79\x2f\x32",
    b"\x06\x73\x70\x64\x79\x2f\x33", b"\x03\x68\x32\x63", b"\x02\x68\x71",
]
GREASE_VALUE = b"\x7a\x7a"  # any GREASE value works; server negotiation ignores it

# Fixed misc extension blocks (verbatim from the reference).
EXT_MASTER_SECRET = b"\x00\x17\x00\x00"
MAX_FRAG_LENGTH   = b"\x00\x01\x00\x01\x01"
RENEGOTIATION     = b"\xff\x01\x00\x01\x00"
SUPPORTED_GROUPS  = b"\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"
EC_POINT_FORMATS  = b"\x00\x0b\x00\x02\x01\x00"
SESSION_TICKET    = b"\x00\x23\x00\x00"
SIGNATURE_ALGOS   = b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01"
PSK_MODES         = b"\x00\x2d\x00\x02\x01\x01"
SUB_1_2_SUPPORT   = [b"\x03\x01", b"\x03\x02", b"\x03\x03"]
TLS_1_3_SUPPORT   = [b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x04"]

# Fuzzy-hash cipher index table (distinct from the offered-cipher lists).
HASH_CIPHER_LIST = [
    "0004", "0005", "0007", "000a", "0016", "002f", "0033", "0035", "0039",
    "003c", "003d", "0041", "0045", "0067", "006b", "0084", "0088", "009a",
    "009c", "009d", "009e", "009f", "00ba", "00be", "00c0", "00c4", "c007",
    "c008", "c009", "c00a", "c011", "c012", "c013", "c014", "c023", "c024",
    "c027", "c028", "c02b", "c02c", "c02f", "c030", "c060", "c061", "c072",
    "c073", "c076", "c077", "c09c", "c09d", "c09e", "c09f", "c0a0", "c0a1",
    "c0a2", "c0a3", "c0ac", "c0ad", "c0ae", "c0af", "cc13", "cc14", "cca8",
    "cca9", "1301", "1302", "1303", "1304", "1305",
]

TOTAL_FAILURE = "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||"
FAILED_PACKET = "|||"
ERROR_INC_1 = b"\x0e\xac\x0b"
ERROR_INC_2 = b"\x0f\xf0\x0b"

# The ten JARM v1 probes, in order. Fields:
# (version, cipher_list, cipher_order, grease, rare_alpn, support, ext_order)
PROBES = [
    ("TLS_1.2", "ALL",   "FORWARD",     False, False, "1.2", "REVERSE"),
    ("TLS_1.2", "ALL",   "REVERSE",     False, False, "1.2", "FORWARD"),
    ("TLS_1.2", "ALL",   "TOP_HALF",    False, False, "NO",  "FORWARD"),
    ("TLS_1.2", "ALL",   "BOTTOM_HALF", False, True,  "NO",  "FORWARD"),
    ("TLS_1.2", "ALL",   "MIDDLE_OUT",  True,  True,  "NO",  "REVERSE"),
    ("TLS_1.1", "ALL",   "FORWARD",     False, False, "NO",  "FORWARD"),
    ("TLS_1.3", "ALL",   "FORWARD",     False, False, "1.3", "REVERSE"),
    ("TLS_1.3", "ALL",   "REVERSE",     False, False, "1.3", "FORWARD"),
    ("TLS_1.3", "NO13",  "FORWARD",     False, False, "1.3", "FORWARD"),
    ("TLS_1.3", "ALL",   "MIDDLE_OUT",  True,  False, "1.3", "REVERSE"),
]

VERSION_BYTES = {
    "TLS_1.1": (b"\x03\x02", b"\x03\x02"),   # (record payload, hello version)
    "TLS_1.2": (b"\x03\x03", b"\x03\x03"),
    "TLS_1.3": (b"\x03\x01", b"\x03\x03"),
}


def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]        Perimetry - JARM TLS Fingerprint")
    console.print(f"[{TEAL}]{bar}\n")


def reorder(seq, order):
    length = len(seq)
    if order == "FORWARD":
        return list(seq)
    if order == "REVERSE":
        return seq[::-1]
    if order == "BOTTOM_HALF":
        return seq[length // 2 + 1:] if length % 2 == 1 else seq[length // 2:]
    if order == "TOP_HALF":
        out = []
        if length % 2 == 1:
            out.append(seq[length // 2])
        out += reorder(reorder(seq, "REVERSE"), "BOTTOM_HALF")
        return out
    if order == "MIDDLE_OUT":
        middle = length // 2
        out = []
        if length % 2 == 1:
            out.append(seq[middle])
            for i in range(1, middle + 1):
                out.append(seq[middle + i])
                out.append(seq[middle - i])
        else:
            for i in range(1, middle + 1):
                out.append(seq[middle - 1 + i])
                out.append(seq[middle - i])
        return out
    return list(seq)


def get_ciphers(spec):
    base = list(ALL_CIPHERS if spec[1] == "ALL" else NO13_CIPHERS)
    base = reorder(base, spec[2])
    if spec[3]:  # grease
        base = [GREASE_VALUE] + base
    return b"".join(base)


def ext_sni(host):
    h = host.encode()
    return (b"\x00\x00" + pack(">H", len(h) + 5) + pack(">H", len(h) + 3)
            + b"\x00" + pack(">H", len(h)) + h)


def ext_alpn(spec):
    alpns = reorder(list(ALPN_RARE if spec[4] else ALPN_ALL), spec[6])
    data = b"".join(alpns)
    return b"\x00\x10" + pack(">H", len(data) + 2) + pack(">H", len(data)) + data


def ext_key_share(grease):
    share = b""
    if grease:
        share += GREASE_VALUE + b"\x00\x01\x00"
    share += b"\x00\x1d" + b"\x00\x20" + os.urandom(32)
    return b"\x00\x33" + pack(">H", len(share) + 2) + pack(">H", len(share)) + share


def ext_supported_versions(spec):
    tls = SUB_1_2_SUPPORT if spec[5] == "1.2" else TLS_1_3_SUPPORT
    tls = reorder(tls, spec[6])
    versions = b""
    if spec[3]:  # grease
        versions += GREASE_VALUE
    versions += b"".join(tls)
    return b"\x00\x2b" + pack(">H", len(versions) + 1) + pack(">B", len(versions)) + versions


def build_extensions(spec, host):
    grease = spec[3]
    exts = b""
    if grease:
        exts += GREASE_VALUE + b"\x00\x00"
    exts += ext_sni(host)
    exts += EXT_MASTER_SECRET
    exts += MAX_FRAG_LENGTH
    exts += RENEGOTIATION
    exts += SUPPORTED_GROUPS
    exts += EC_POINT_FORMATS
    exts += SESSION_TICKET
    exts += ext_alpn(spec)
    exts += SIGNATURE_ALGOS
    exts += ext_key_share(grease)
    exts += PSK_MODES
    # supported_versions only for TLS 1.3 probes or explicit 1.2 support
    if spec[0] == "TLS_1.3" or spec[5] == "1.2":
        exts += ext_supported_versions(spec)
    return pack(">H", len(exts)) + exts


def build_packet(spec, host):
    payload_ver, hello_ver = VERSION_BYTES[spec[0]]
    payload = b"\x16" + payload_ver
    client_hello = hello_ver + os.urandom(32)
    session_id = os.urandom(32)
    client_hello += pack(">B", len(session_id)) + session_id
    ciphers = get_ciphers(spec)
    client_hello += pack(">H", len(ciphers)) + ciphers
    client_hello += b"\x01\x00"                       # compression: null
    client_hello += build_extensions(spec, host)

    handshake = b"\x01" + b"\x00" + pack(">H", len(client_hello)) + client_hello
    payload += pack(">H", len(handshake)) + handshake
    return payload


def send_probe(host, port, spec, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(build_packet(spec, host))
        data = sock.recv(1484)
        sock.close()
        return data
    except (socket.timeout, socket.error, OSError):
        return None


def parse_server_hello(data):
    """Return the reference 'cipher|version|alpn|types' string for one probe."""
    if data is None or len(data) < 6:
        return FAILED_PACKET
    if data[0] == 21:                       # TLS alert
        return FAILED_PACKET
    if not (data[0] == 22 and data[5] == 2):
        return FAILED_PACKET
    try:
        counter = data[43]
        cipher = data[counter + 44:counter + 46]
        version = data[9:11]
        return f"{cipher.hex()}|{version.hex()}|{extract_extension_info(data, counter)}"
    except (IndexError, ValueError):
        return FAILED_PACKET


def extract_extension_info(data, counter):
    try:
        if (data[counter + 47] == 11
                or data[counter + 50:counter + 53] == ERROR_INC_1
                or data[82:85] == ERROR_INC_2):
            return FAILED_PACKET
        count = 49 + counter
        length = int.from_bytes(data[counter + 47:counter + 49], "big")
        maximum = length + (count - 1)
        types, values = [], []
        while count < maximum:
            types.append(data[count:count + 2])
            ext_len = int.from_bytes(data[count + 2:count + 4], "big")
            if ext_len == 0:
                count += 4
                values.append(b"")
            else:
                values.append(data[count + 4:count + 4 + ext_len])
                count += ext_len + 4
        alpn = ""
        for t, v in zip(types, values):
            if t == b"\x00\x10":
                alpn = v[3:].decode(errors="replace")
                break
        result = f"{alpn}|"
        result += "-".join(t.hex() for t in types)
        return result
    except (IndexError, ValueError):
        return "|"


def jarm_hash(raw):
    if raw == TOTAL_FAILURE:
        return "0" * 62
    fuzzy = ""
    alpns_and_ext = ""
    for handshake in raw.split(","):
        c = handshake.split("|")
        fuzzy += cipher_byte(c[0] if len(c) > 0 else "")
        fuzzy += version_byte(c[1] if len(c) > 1 else "")
        alpns_and_ext += (c[2] if len(c) > 2 else "")
        alpns_and_ext += (c[3] if len(c) > 3 else "")
    fuzzy += hashlib.sha256(alpns_and_ext.encode()).hexdigest()[0:32]
    return fuzzy


def cipher_byte(cipher):
    if cipher == "":
        return "00"
    count = 1
    for hexstr in HASH_CIPHER_LIST:
        if cipher == hexstr:
            break
        count += 1
    h = format(count, "x")
    return h if len(h) == 2 else "0" + h


def version_byte(version):
    if version == "" or len(version) < 4:
        return "0"
    try:
        return "abcdef"[int(version[3:4])]
    except (ValueError, IndexError):
        return "0"


def run(target, threads, opts):
    banner()
    timeout = int(opts.get("timeout", 8))
    port = int(opts.get("port", 443))
    dom = clean_domain_input(target)
    start = time.time()

    try:
        ip = socket.gethostbyname(dom)
    except socket.gaierror:
        console.print(f"[red]✖ Could not resolve {dom}[/red]")
        return

    console.print(f"[white]* Fingerprinting {dom} ({ip}:{port}) with 10 TLS probes[/white]")
    raws = []
    tbl = Table(title="JARM Probes", header_style="bold white", box=box.MINIMAL)
    tbl.add_column("#", justify="right")
    tbl.add_column("Probe", style="cyan")
    tbl.add_column("Cipher", style="green")
    tbl.add_column("Ver")
    for i, spec in enumerate(PROBES, 1):
        raw = parse_server_hello(send_probe(dom, port, spec, timeout))
        raws.append(raw)
        f = raw.split("|")
        tbl.add_row(str(i), f"{spec[0]} {spec[2]}",
                    f[0] if f[0] else "—", f[1] if len(f) > 1 and f[1] else "—")
    console.print(tbl)

    fp = jarm_hash(",".join(raws))
    answered = sum(1 for r in raws if r != FAILED_PACKET)
    is_zero = fp == "0" * 62
    fcolor = "bold green" if answered and not is_zero else "red"
    summary = (
        f"JARM: {fp}\n"
        f"Host: {dom} ({ip}:{port})   Probes answered: {answered}/10   "
        f"Elapsed: {time.time()-start:.2f}s"
    )
    console.print(Panel(f"[{fcolor}]{fp}[/{fcolor}]\n{summary}", title="JARM Fingerprint", style=fcolor))
    if is_zero:
        console.print("[yellow]All-zero JARM: no TLS handshake completed on this port.[/yellow]")
    console.print("[green][*] JARM fingerprint completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out)
        rec = Console(record=True, file=io.StringIO(), width=console.width)
        rec.print(tbl)
        rec.print(Panel(summary, title="JARM Fingerprint"))
        # Write UTF-8 explicitly: the report contains box-drawing glyphs that the
        # Windows default codepage (cp1252) cannot encode.
        with open(os.path.join(out, "jarm_tls_fingerprint.txt"), "w", encoding="utf-8") as fh:
            fh.write(rec.export_text())


if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else ""
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except json.JSONDecodeError:
            pass
    run(tgt, thr, opts)
