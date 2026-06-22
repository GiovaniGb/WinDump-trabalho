import struct
import socket
import ipaddress
from pathlib import Path


PCAP_LINKTYPE_ETHERNET = 1

IPPROTO_HOPOPTS = 0
IPPROTO_UDP = 17
IPPROTO_DSTOPTS = 60

ETHERTYPE_IPV6 = 0x86DD

OPT_PAD1 = 0x00
OPT_PADN = 0x01
OPT_ALTMARK = 0x12
OPT_IOAM = 0x31
OPT_PDM = 0x0F


def checksum(data: bytes) -> int:
    """Internet checksum."""
    if len(data) % 2:
        data += b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def udp_checksum(src_ip: str, dst_ip: str, udp_segment: bytes) -> int:
    src = ipaddress.IPv6Address(src_ip).packed
    dst = ipaddress.IPv6Address(dst_ip).packed
    udp_len = len(udp_segment)

    pseudo_header = (
        src +
        dst +
        struct.pack("!I", udp_len) +
        b"\x00" * 3 +
        struct.pack("!B", IPPROTO_UDP)
    )

    return checksum(pseudo_header + udp_segment)


def build_udp(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    udp_len = 8 + len(payload)

    udp_without_checksum = struct.pack(
        "!HHHH",
        src_port,
        dst_port,
        udp_len,
        0
    ) + payload

    csum = udp_checksum(src_ip, dst_ip, udp_without_checksum)

    return struct.pack(
        "!HHHH",
        src_port,
        dst_port,
        udp_len,
        csum
    ) + payload


def pad_options_for_ext_header(options: bytes) -> bytes:
    """
    IPv6 extension header length must be multiple of 8 bytes.
    Header has 2 fixed bytes: Next Header + Hdr Ext Len.
    """
    current_len = 2 + len(options)
    pad_len = (-current_len) % 8

    if pad_len == 0:
        return options

    if pad_len == 1:
        return options + bytes([OPT_PAD1])

    # PadN: option type 1, length N-2, then zeros
    return options + bytes([OPT_PADN, pad_len - 2]) + (b"\x00" * (pad_len - 2))


def build_extension_header(next_header: int, options: bytes) -> bytes:
    padded_options = pad_options_for_ext_header(options)
    total_len = 2 + len(padded_options)

    if total_len % 8 != 0:
        raise ValueError("Extension header length is not multiple of 8")

    hdr_ext_len = (total_len // 8) - 1

    return struct.pack("!BB", next_header, hdr_ext_len) + padded_options


def build_ipv6_header(
    src_ip: str,
    dst_ip: str,
    next_header: int,
    payload_len: int,
    flow_label: int,
    hop_limit: int = 64,
    traffic_class: int = 0
) -> bytes:
    version_tc_fl = (
        (6 << 28) |
        ((traffic_class & 0xFF) << 20) |
        (flow_label & 0xFFFFF)
    )

    return (
        struct.pack("!IHBB", version_tc_fl, payload_len, next_header, hop_limit) +
        ipaddress.IPv6Address(src_ip).packed +
        ipaddress.IPv6Address(dst_ip).packed
    )


def build_ethernet_frame(src_mac: bytes, dst_mac: bytes, ethertype: int, payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", ethertype) + payload


def altmark_option(flowmonid: int, loss: int, delay: int) -> bytes:
    """
    IPv6 AltMark option.

    Option Type: 0x12
    Opt Data Len: 4

    Encodificação usada:
    - FlowMonID em 20 bits superiores
    - L/loss no bit 11
    - D/delay no bit 10
    """
    value = ((flowmonid & 0xFFFFF) << 12) | ((loss & 1) << 11) | ((delay & 1) << 10)
    data = struct.pack("!I", value)

    return struct.pack("!BB", OPT_ALTMARK, len(data)) + data


def ioam_prealloc_trace_option(
    namespace_id: int = 0x0000,
    trace_type: int = 0x000000,
    node_data: bytes = b"",
    flags_remlen: int = 0x00
) -> bytes:
    """
    IOAM Pre-allocated Trace option for IPv6.

    IPv6 Option Type: 0x31
    IOAM Opt-Type: 0x00, pre-allocated trace

    Para trace-type 0xc00000, o node_data usado aqui é:
    - 1 byte Hop Limit
    - 3 bytes Node ID curto
    - 2 bytes Ingress Interface ID
    - 2 bytes Egress Interface ID
    """
    ioam_opt_type = 0x00
    reserved = 0x00

    if len(node_data) % 4 != 0:
        raise ValueError("IOAM node_data must be multiple of 4 bytes")

    node_len_units = len(node_data) // 4

    # O tcpdump/WinDump interpreta 0x10 como nodelen 2.
    # Portanto, codificamos nodelen em unidades de 4 bytes deslocado 3 bits.
    node_len_encoded = (node_len_units & 0x1F) << 3

    trace_type_24 = bytes([
        (trace_type >> 16) & 0xFF,
        (trace_type >> 8) & 0xFF,
        trace_type & 0xFF
    ])

    # 10 bytes fixos de dados IOAM + dados do nó
    data = (
        struct.pack("!H", namespace_id & 0xFFFF) +
        struct.pack("!B", ioam_opt_type) +
        struct.pack("!B", reserved) +
        struct.pack("!B", node_len_encoded) +
        struct.pack("!B", flags_remlen & 0xFF) +
        trace_type_24 +
        b"\x00" +
        node_data
    )

    return struct.pack("!BB", OPT_IOAM, len(data)) + data


def ioam_node_data_short(hop_limit: int, node_id_short: int, ingress_if: int, egress_if: int) -> bytes:
    """
    Dados para trace-type 0xc00000:
    - Hop Limit + Node ID curto
    - Ingress IF ID + Egress IF ID curtos
    """
    return (
        struct.pack("!B", hop_limit & 0xFF) +
        node_id_short.to_bytes(3, "big") +
        struct.pack("!HH", ingress_if & 0xFFFF, egress_if & 0xFFFF)
    )


def pdm_option(
    psn_this: int,
    psn_last: int,
    delta_last_recv: int,
    delta_last_sent: int,
    scale_recv: int = 0,
    scale_sent: int = 0
) -> bytes:
    """
    IPv6 PDM Destination Option.

    Option Type: 0x0F
    Opt Data Len: 10

    Primeiro byte:
    - nibble alto: escala de recebimento
    - nibble baixo: escala de envio
    """
    scale_byte = ((scale_recv & 0x0F) << 4) | (scale_sent & 0x0F)

    data = (
        struct.pack("!B", scale_byte) +
        b"\x00" +
        struct.pack("!H", psn_this & 0xFFFF) +
        struct.pack("!H", psn_last & 0xFFFF) +
        struct.pack("!H", delta_last_recv & 0xFFFF) +
        struct.pack("!H", delta_last_sent & 0xFFFF)
    )

    return struct.pack("!BB", OPT_PDM, len(data)) + data


def build_ipv6_packet(
    src_ip: str,
    dst_ip: str,
    flow_label: int,
    udp_src_port: int,
    udp_dst_port: int,
    udp_payload: bytes,
    hbh_options: bytes = b"",
    dst_options: bytes = b"",
    src_mac: bytes = b"\x02\x00\x00\x00\x00\x01",
    dst_mac: bytes = b"\x02\x00\x00\x00\x01\x01"
) -> bytes:
    udp = build_udp(src_ip, dst_ip, udp_src_port, udp_dst_port, udp_payload)

    extension_chain = b""

    if hbh_options and dst_options:
        dst_header = build_extension_header(IPPROTO_UDP, dst_options)
        hbh_header = build_extension_header(IPPROTO_DSTOPTS, hbh_options)
        ipv6_next_header = IPPROTO_HOPOPTS
        extension_chain = hbh_header + dst_header

    elif hbh_options:
        hbh_header = build_extension_header(IPPROTO_UDP, hbh_options)
        ipv6_next_header = IPPROTO_HOPOPTS
        extension_chain = hbh_header

    elif dst_options:
        dst_header = build_extension_header(IPPROTO_UDP, dst_options)
        ipv6_next_header = IPPROTO_DSTOPTS
        extension_chain = dst_header

    else:
        ipv6_next_header = IPPROTO_UDP

    ipv6_payload = extension_chain + udp

    ipv6_header = build_ipv6_header(
        src_ip=src_ip,
        dst_ip=dst_ip,
        next_header=ipv6_next_header,
        payload_len=len(ipv6_payload),
        flow_label=flow_label
    )

    frame = build_ethernet_frame(
        src_mac=src_mac,
        dst_mac=dst_mac,
        ethertype=ETHERTYPE_IPV6,
        payload=ipv6_header + ipv6_payload
    )

    return frame


def write_pcap(filename: str, packets: list[bytes]) -> None:
    with open(filename, "wb") as f:
        # PCAP global header, little-endian
        f.write(struct.pack(
            "<IHHIIII",
            0xA1B2C3D4,
            2,
            4,
            0,
            0,
            65535,
            PCAP_LINKTYPE_ETHERNET
        ))

        base_ts = 1710000000

        for i, pkt in enumerate(packets):
            ts_sec = base_ts + i
            ts_usec = i * 1000

            f.write(struct.pack(
                "<IIII",
                ts_sec,
                ts_usec,
                len(pkt),
                len(pkt)
            ))

            f.write(pkt)


def main():
    packets = []

    # Pacote 1: apenas AltMark em Hop-by-Hop, medição de perda
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:1::1",
        dst_ip="2001:db8:1::2",
        flow_label=0xA9343,
        udp_src_port=10001,
        udp_dst_port=20001,
        udp_payload=b"ALT1",
        hbh_options=altmark_option(flowmonid=0xABCDE, loss=1, delay=0),
        src_mac=b"\x02\x00\x00\x00\x00\x01",
        dst_mac=b"\x02\x00\x00\x00\x01\x01"
    ))

    # Pacote 2: apenas AltMark em Hop-by-Hop, medição de atraso
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:1::3",
        dst_ip="2001:db8:1::4",
        flow_label=0xA9344,
        udp_src_port=10002,
        udp_dst_port=20002,
        udp_payload=b"ALT2",
        hbh_options=altmark_option(flowmonid=0xABCDE, loss=0, delay=1),
        src_mac=b"\x02\x00\x00\x00\x00\x02",
        dst_mac=b"\x02\x00\x00\x00\x01\x02"
    ))

    # Pacote 3: AltMark em Destination Options
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:1::5",
        dst_ip="2001:db8:1::6",
        flow_label=0xA9345,
        udp_src_port=10003,
        udp_dst_port=20003,
        udp_payload=b"ALTDST",
        dst_options=altmark_option(flowmonid=0x12345, loss=1, delay=1),
        src_mac=b"\x02\x00\x00\x00\x00\x03",
        dst_mac=b"\x02\x00\x00\x00\x01\x03"
    ))

    # Pacote 4: IOAM mínimo, sem área de trace preenchida
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:2::1",
        dst_ip="2001:db8:2::2",
        flow_label=0xA9486,
        udp_src_port=10004,
        udp_dst_port=20004,
        udp_payload=b"IOAM0",
        hbh_options=b"\x00\x00" + ioam_prealloc_trace_option(
            namespace_id=0x0000,
            trace_type=0x000000,
            node_data=b""
        ),
        src_mac=b"\x02\x00\x00\x00\x00\x04",
        dst_mac=b"\x02\x00\x00\x00\x01\x04"
    ))

    # Pacote 5: IOAM com trace preenchido, nó A
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:2::3",
        dst_ip="2001:db8:2::4",
        flow_label=0xA9487,
        udp_src_port=10005,
        udp_dst_port=20005,
        udp_payload=b"IOAMA",
        hbh_options=b"\x00\x00" + ioam_prealloc_trace_option(
            namespace_id=0x0001,
            trace_type=0xC00000,
            node_data=ioam_node_data_short(
                hop_limit=63,
                node_id_short=0x010203,
                ingress_if=0x0010,
                egress_if=0x0020
            )
        ),
        src_mac=b"\x02\x00\x00\x00\x00\x05",
        dst_mac=b"\x02\x00\x00\x00\x01\x05"
    ))

    # Pacote 6: IOAM com trace preenchido, nó B
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:2::5",
        dst_ip="2001:db8:2::6",
        flow_label=0xA9488,
        udp_src_port=10006,
        udp_dst_port=20006,
        udp_payload=b"IOAMB",
        hbh_options=b"\x00\x00" + ioam_prealloc_trace_option(
            namespace_id=0x0002,
            trace_type=0xC00000,
            node_data=ioam_node_data_short(
                hop_limit=62,
                node_id_short=0x0A0B0C,
                ingress_if=0x0030,
                egress_if=0x0040
            )
        ),
        src_mac=b"\x02\x00\x00\x00\x00\x06",
        dst_mac=b"\x02\x00\x00\x00\x01\x06"
    ))

    # Pacote 7: apenas PDM básico
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:3::1",
        dst_ip="2001:db8:3::2",
        flow_label=0xA8250,
        udp_src_port=10007,
        udp_dst_port=20007,
        udp_payload=b"PDM1",
        dst_options=pdm_option(
            psn_this=1,
            psn_last=0,
            delta_last_recv=16,
            delta_last_sent=32,
            scale_recv=0,
            scale_sent=0
        ),
        src_mac=b"\x02\x00\x00\x00\x00\x07",
        dst_mac=b"\x02\x00\x00\x00\x01\x07"
    ))

    # Pacote 8: PDM com valores diferentes
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:3::3",
        dst_ip="2001:db8:3::4",
        flow_label=0xA8251,
        udp_src_port=10008,
        udp_dst_port=20008,
        udp_payload=b"PDM2",
        dst_options=pdm_option(
            psn_this=25,
            psn_last=24,
            delta_last_recv=120,
            delta_last_sent=240,
            scale_recv=1,
            scale_sent=2
        ),
        src_mac=b"\x02\x00\x00\x00\x00\x08",
        dst_mac=b"\x02\x00\x00\x00\x01\x08"
    ))

    # Pacote 9: AltMark + IOAM
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:4::1",
        dst_ip="2001:db8:4::2",
        flow_label=0xAA001,
        udp_src_port=10009,
        udp_dst_port=20009,
        udp_payload=b"ALTIOAM",
        hbh_options=
            altmark_option(flowmonid=0xAAAAA, loss=1, delay=0) +
            ioam_prealloc_trace_option(
                namespace_id=0x0010,
                trace_type=0xC00000,
                node_data=ioam_node_data_short(
                    hop_limit=60,
                    node_id_short=0x111111,
                    ingress_if=0x0101,
                    egress_if=0x0102
                )
            ),
        src_mac=b"\x02\x00\x00\x00\x00\x09",
        dst_mac=b"\x02\x00\x00\x00\x01\x09"
    ))

    # Pacote 10: AltMark + PDM
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:4::3",
        dst_ip="2001:db8:4::4",
        flow_label=0xAA002,
        udp_src_port=10010,
        udp_dst_port=20010,
        udp_payload=b"ALTPDM",
        hbh_options=altmark_option(flowmonid=0xBBBBB, loss=0, delay=1),
        dst_options=pdm_option(
            psn_this=100,
            psn_last=99,
            delta_last_recv=40,
            delta_last_sent=80,
            scale_recv=0,
            scale_sent=1
        ),
        src_mac=b"\x02\x00\x00\x00\x00\x0a",
        dst_mac=b"\x02\x00\x00\x00\x01\x0a"
    ))

    # Pacote 11: IOAM + PDM
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:4::5",
        dst_ip="2001:db8:4::6",
        flow_label=0xAA003,
        udp_src_port=10011,
        udp_dst_port=20011,
        udp_payload=b"IOAMPDM",
        hbh_options=b"\x00\x00" + ioam_prealloc_trace_option(
            namespace_id=0x0020,
            trace_type=0xC00000,
            node_data=ioam_node_data_short(
                hop_limit=59,
                node_id_short=0x222222,
                ingress_if=0x0201,
                egress_if=0x0202
            )
        ),
        dst_options=pdm_option(
            psn_this=200,
            psn_last=199,
            delta_last_recv=50,
            delta_last_sent=100,
            scale_recv=1,
            scale_sent=1
        ),
        src_mac=b"\x02\x00\x00\x00\x00\x0b",
        dst_mac=b"\x02\x00\x00\x00\x01\x0b"
    ))

    # Pacote 12: AltMark + IOAM + PDM
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:5::1",
        dst_ip="2001:db8:5::2",
        flow_label=0xABC01,
        udp_src_port=10012,
        udp_dst_port=20012,
        udp_payload=b"ALL1",
        hbh_options=
            altmark_option(flowmonid=0xABCDE, loss=1, delay=0) +
            ioam_prealloc_trace_option(
                namespace_id=0x0030,
                trace_type=0xC00000,
                node_data=ioam_node_data_short(
                    hop_limit=63,
                    node_id_short=0x010203,
                    ingress_if=0x0010,
                    egress_if=0x0020
                )
            ),
        dst_options=pdm_option(
            psn_this=1,
            psn_last=0,
            delta_last_recv=16,
            delta_last_sent=32,
            scale_recv=0,
            scale_sent=0
        ),
        src_mac=b"\x02\x00\x00\x00\x00\x0c",
        dst_mac=b"\x02\x00\x00\x00\x01\x0c"
    ))

    # Pacote 13: AltMark + IOAM + PDM, variação com delay
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:5::3",
        dst_ip="2001:db8:5::4",
        flow_label=0xABC02,
        udp_src_port=10013,
        udp_dst_port=20013,
        udp_payload=b"ALL2",
        hbh_options=
            altmark_option(flowmonid=0xABCDE, loss=0, delay=1) +
            ioam_prealloc_trace_option(
                namespace_id=0x0031,
                trace_type=0xC00000,
                node_data=ioam_node_data_short(
                    hop_limit=61,
                    node_id_short=0x030405,
                    ingress_if=0x0031,
                    egress_if=0x0032
                )
            ),
        dst_options=pdm_option(
            psn_this=2,
            psn_last=1,
            delta_last_recv=20,
            delta_last_sent=45,
            scale_recv=0,
            scale_sent=1
        ),
        src_mac=b"\x02\x00\x00\x00\x00\x0d",
        dst_mac=b"\x02\x00\x00\x00\x01\x0d"
    ))

    # Pacote 14: AltMark + IOAM + PDM, perda e atraso
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:5::5",
        dst_ip="2001:db8:5::6",
        flow_label=0xABC03,
        udp_src_port=10014,
        udp_dst_port=20014,
        udp_payload=b"ALL3",
        hbh_options=
            altmark_option(flowmonid=0xFEDCB, loss=1, delay=1) +
            ioam_prealloc_trace_option(
                namespace_id=0x0032,
                trace_type=0xC00000,
                node_data=ioam_node_data_short(
                    hop_limit=58,
                    node_id_short=0x050607,
                    ingress_if=0x0041,
                    egress_if=0x0042
                )
            ),
        dst_options=pdm_option(
            psn_this=300,
            psn_last=299,
            delta_last_recv=64,
            delta_last_sent=128,
            scale_recv=2,
            scale_sent=2
        ),
        src_mac=b"\x02\x00\x00\x00\x00\x0e",
        dst_mac=b"\x02\x00\x00\x00\x01\x0e"
    ))

    # Pacote 15: IOAM em Hop-by-Hop + AltMark e PDM em Destination Options
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:6::1",
        dst_ip="2001:db8:6::2",
        flow_label=0xABC04,
        udp_src_port=10015,
        udp_dst_port=20015,
        udp_payload=b"MIXED",
        hbh_options=b"\x00\x00" + ioam_prealloc_trace_option(
            namespace_id=0x0040,
            trace_type=0xC00000,
            node_data=ioam_node_data_short(
                hop_limit=57,
                node_id_short=0x08090A,
                ingress_if=0x0051,
                egress_if=0x0052
            )
        ),
        dst_options=
            altmark_option(flowmonid=0x11111, loss=1, delay=0) +
            pdm_option(
                psn_this=400,
                psn_last=399,
                delta_last_recv=90,
                delta_last_sent=180,
                scale_recv=1,
                scale_sent=3
            ),
        src_mac=b"\x02\x00\x00\x00\x00\x0f",
        dst_mac=b"\x02\x00\x00\x00\x01\x0f"
    ))

    output_file = "pacotes_teste.pcap"
    write_pcap(output_file, packets)

    print(f"Arquivo gerado: {output_file}")
    print(f"Total de pacotes: {len(packets)}")


if __name__ == "__main__":
    main()