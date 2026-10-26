#!/usr/bin/env python3
"""Regenerates the seed corpora under mayhem/<target>/testsuite/ (run from the repo root)."""
import os
import struct

ROOT = os.path.dirname(os.path.abspath(__file__))
MACS = bytes([0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB])


def write(target, name, data):
    d = os.path.join(ROOT, target, "testsuite")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


def sip(method="INVITE", body=b"", extra=b"", resp=None):
    start = (f"SIP/2.0 {resp}" if resp else f"{method} sip:bob@biloxi.example.com SIP/2.0").encode()
    hdr = (b"\r\nVia: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds"
           b"\r\nTo: Bob <sip:bob@biloxi.example.com>"
           b"\r\nFrom: Alice <sip:alice@atlanta.example.com>;tag=1928301774"
           b"\r\nCall-ID: a84b4c76e66710@pc33.atlanta.example.com"
           b"\r\nCSeq: 314159 " + method.encode() +
           b"\r\nContact: <sip:alice@pc33.atlanta.example.com>" + extra)
    if body:
        hdr += b"\r\nContent-Type: application/sdp\r\nContent-Length: %d" % len(body)
    else:
        hdr += b"\r\nContent-Length: 0"
    return start + hdr + b"\r\n\r\n" + body


SDP = (b"v=0\r\no=alice 2890844526 2890844526 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\n"
       b"m=audio 49170 RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtcp:49171 IN IP4 10.0.0.1\r\n")
RTCPXR = (b"VQSessionReport: CallTerm\r\nCallID: a84b4c76e66710@pc33.atlanta.example.com\r\n"
          b"LocalMetrics:\r\nTimestamps:START=2021-01-01T00:00:00Z STOP=2021-01-01T00:01:00Z\r\n"
          b"SessionDesc:PT=0 PD=PCMU SR=8000 FD=20 FO=20 PLC=3\r\nJitterBuffer:JBA=3 JBR=2 JBN=40 JBM=80 JBS=0\r\n"
          b"PacketLoss:NLR=5.0 JDR=2.0\r\nBurstGapLoss:BLD=0 BD=0 GLD=0 GD=0 GMIN=16\r\n"
          b"Delay:RTD=20 ESD=10 IAJ=2\r\nQualityEst:MOSLQ=4.1 MOSCQ=4.0\r\n")

for i, (name, m) in enumerate({
    "invite": sip(), "ok": sip(resp="200 OK"), "invite_sdp": sip(body=SDP),
    "register": sip("REGISTER", extra=b"\r\nExpires: 3600"), "bye": sip("BYE"),
    "options": sip("OPTIONS"), "trying": sip(resp="100 Trying"),
    "publish_rtcpxr": sip("PUBLISH", body=RTCPXR), "notfound": sip("INVITE", resp="404 Not Found"),
    "pai": sip(extra=b"\r\nP-Asserted-Identity: <sip:+15551230000@example.com>\r\nUser-Agent: seed/1.0\r\nRoute: <sip:p1.example.com;lr>"),
}.items()):
    for mode in (0, 1):
        write("fuzz_sip_parser", f"{name}_{mode}", bytes([mode]) + m)


def u16(v): return struct.pack(">H", v)


def ipv4(proto, payload, ident=0x1234, flags_off=0, src=(10, 0, 0, 1), dst=(10, 0, 0, 2), ihl=5):
    h = bytes([0x40 | ihl, 0]) + u16(ihl * 4 + len(payload)) + u16(ident) + u16(flags_off) + bytes([64, proto]) + u16(0)
    h += bytes(src) + bytes(dst) + b"\0" * ((ihl - 5) * 4)
    return h + payload


def udp(payload, sport=5060, dport=5080): return u16(sport) + u16(dport) + u16(8 + len(payload)) + u16(0) + payload


def tcp(payload, flags=0x18, seq=1000, sport=5060, dport=5080):
    return (u16(sport) + u16(dport) + struct.pack(">II", seq, 1) + bytes([0x50, flags]) + u16(8192) + u16(0) + u16(0) + payload)


def eth(ip, vlan=False):
    return MACS + (u16(0x8100) + u16(100) if vlan else b"") + u16(0x0800) + ip


def pkts(*ps):
    return b"".join(struct.pack("<H", len(p)) + p for p in ps)


INV = sip()
OK = sip(resp="200 OK")
# cfg bits: 0-2 link type, 3 ip reasm, 4 tcp reasm, 5 erspan, 6 websocket, 7 full_packet
cases = {
    "eth_udp": (0, [eth(ipv4(17, udp(INV)))]),
    "eth_udp_two": (0, [eth(ipv4(17, udp(INV))), eth(ipv4(17, udp(OK, 5080, 5060), src=(10, 0, 0, 2), dst=(10, 0, 0, 1)))]),
    "eth_vlan_udp": (0, [eth(ipv4(17, udp(INV)), vlan=True)]),
    "eth_tcp": (0, [eth(ipv4(6, tcp(INV)))]),
    "eth_tcp_reasm": (0x10, [eth(ipv4(6, tcp(INV[:100], seq=1000))), eth(ipv4(6, tcp(INV[100:], seq=1100)))]),
    "eth_tcp_ws": (0x40, [eth(ipv4(6, tcp(b"\x81" + bytes([len(INV) & 0x7f]) + INV[:125])))]),
    "eth_ip_frag": (0x08, [eth(ipv4(17, udp(INV)[:24], flags_off=0x2000)), eth(ipv4(17, udp(INV)[24:], flags_off=3))]),
    "eth_udp_full": (0x80, [eth(ipv4(17, udp(INV)))]),
    "eth_icmp": (0, [eth(ipv4(1, b"\x08\x00\x00\x00\x00\x01\x00\x01"))]),
    "eth_sctp": (0, [eth(ipv4(132, u16(5060) + u16(5061) + b"\0" * 8 + INV[:40]))]),
    "eth_ipip": (0, [eth(ipv4(4, ipv4(17, udp(INV))))]),
    "sll_udp": (1, [b"\0\0\0\x01\0\x06" + MACS[:6] + b"\0\0" + u16(0x0800) + ipv4(17, udp(INV))]),
    "raw_udp": (3, [ipv4(17, udp(INV))]),
    "mtp2": (4, [b"\x81\x07\x01\x02\x03\x04\x05\x06\x07"]),
    "null_udp": (5, [b"\x02\0\0\0" + ipv4(17, udp(INV))]),
    "ppp_udp": (6, [b"\xff\x03\x00\x21" + ipv4(17, udp(INV))]),
    "eth_gre_udp": (0x20, [eth(ipv4(47, b"\x00\x00\x08\x00" + ipv4(17, udp(INV))))]),
}
for name, (cfg, ps) in cases.items():
    write("fuzz_socket_pcap", name, bytes([cfg]) + pkts(*ps))
