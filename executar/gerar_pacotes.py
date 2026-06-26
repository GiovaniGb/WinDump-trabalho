import struct
import ipaddress


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
    udp_without_checksum = struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload
    csum = udp_checksum(src_ip, dst_ip, udp_without_checksum)
    return struct.pack("!HHHH", src_port, dst_port, udp_len, csum) + payload


def pad_options_for_ext_header(options: bytes) -> bytes:
    current_len = 2 + len(options)
    pad_len = (-current_len) % 8

    if pad_len == 0:
        return options
    if pad_len == 1:
        return options + bytes([OPT_PAD1])

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
    value = ((flowmonid & 0xFFFFF) << 12) | ((loss & 1) << 11) | ((delay & 1) << 10)
    data = struct.pack("!I", value)
    return struct.pack("!BB", OPT_ALTMARK, len(data)) + data


def ioam_pot_option(
    namespace_id: int = 0x0000,
    packet_id: int = 0x0000000000000001,
    cumulative: int = 0x0000000000000000,
    pot_type: int = 0x00,
    pot_flags: int = 0x00
) -> bytes:

    if pot_type != 0x00:
        raise ValueError("Para simular IOAM POT real, use pot_type=0x00")

    if pot_flags != 0x00:
        raise ValueError("POT Flags ainda não são definidas; use pot_flags=0x00")

    ioam_reserved = 0x00
    ioam_type = 0x02  # IOAM POT Option-Type

    pot_data = struct.pack(
        "!QQ",
        packet_id & 0xFFFFFFFFFFFFFFFF,
        cumulative & 0xFFFFFFFFFFFFFFFF
    )

    data = (
        struct.pack("!B", ioam_reserved) +
        struct.pack("!B", ioam_type) +
        struct.pack("!H", namespace_id & 0xFFFF) +
        struct.pack("!B", pot_type & 0xFF) +
        struct.pack("!B", pot_flags & 0xFF) +
        pot_data
    )

    return struct.pack("!BB", OPT_IOAM, len(data)) + data


def ioam_unsupported_option(ioam_type: int = 0x01, raw_data: bytes = b"") -> bytes:
    ioam_reserved = 0x00
    data = (
        struct.pack("!B", ioam_reserved) +
        struct.pack("!B", ioam_type & 0xFF) +
        raw_data
    )
    return struct.pack("!BB", OPT_IOAM, len(data)) + data


def pdm_option(
    psn_this: int,
    psn_last: int,
    delta_last_recv: int,
    delta_last_sent: int,
    scale_recv: int = 0,
    scale_sent: int = 0
) -> bytes:
    data = (
        struct.pack("!B", scale_recv & 0xFF) +
        struct.pack("!B", scale_sent & 0xFF) +
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
    ipv6_header = build_ipv6_header(src_ip, dst_ip, ipv6_next_header, len(ipv6_payload), flow_label)

    return build_ethernet_frame(
        src_mac=src_mac,
        dst_mac=dst_mac,
        ethertype=ETHERTYPE_IPV6,
        payload=ipv6_header + ipv6_payload
    )


def write_pcap(filename: str, packets: list[bytes]) -> None:
    with open(filename, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, PCAP_LINKTYPE_ETHERNET))

        base_ts = 1710000000
        for i, pkt in enumerate(packets):
            ts_sec = base_ts + i
            ts_usec = i * 1000
            f.write(struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt)))
            f.write(pkt)


def main():
    packets = []

    # 1º - AltMark só com loss
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:1::1",
        dst_ip="2001:db8:1::2",
        flow_label=0xA9343,
        udp_src_port=10001,
        udp_dst_port=20001,
        udp_payload=b"ALT_LOSS",
        hbh_options=altmark_option(
            flowmonid=0xABCDE,
            loss=1,
            delay=0
        ),
        src_mac=b"\x02\x00\x00\x00\x00\x01",
        dst_mac=b"\x02\x00\x00\x00\x01\x01"
    ))

    # 2º - AltMark com delay e loss
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:2::1",
        dst_ip="2001:db8:2::2",
        flow_label=0xA8250,
        udp_src_port=10002,
        udp_dst_port=20002,
        udp_payload=b"ALT_DL",
        hbh_options=altmark_option(
            flowmonid=0xABCDE,
            loss=1,
            delay=1
        ),
        src_mac=b"\x02\x00\x00\x00\x00\x02",
        dst_mac=b"\x02\x00\x00\x00\x01\x02"
    ))

    # 3º - PDM
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:3::1",
        dst_ip="2001:db8:3::2",
        flow_label=0xA9488,
        udp_src_port=10003,
        udp_dst_port=20003,
        udp_payload=b"PDM",
        dst_options=pdm_option(
            psn_this=25,
            psn_last=24,
            delta_last_recv=120,
            delta_last_sent=240,
            scale_recv=1,
            scale_sent=2
        ),
        src_mac=b"\x02\x00\x00\x00\x00\x03",
        dst_mac=b"\x02\x00\x00\x00\x01\x03"
    ))

    # 4º - IOAM POT realista
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:4::1",
        dst_ip="2001:db8:4::2",
        flow_label=0xABC01,
        udp_src_port=10004,
        udp_dst_port=20004,
        udp_payload=b"IOAM_POT",
        hbh_options=ioam_pot_option(
            namespace_id=0x0002,
            packet_id=0x0000000000000001,
            cumulative=0x1234567890ABCDEF
        ),
        src_mac=b"\x02\x00\x00\x00\x00\x04",
        dst_mac=b"\x02\x00\x00\x00\x01\x04"
    ))

    # 5º - AltMark + PDM + IOAM POT juntos
    packets.append(build_ipv6_packet(
        src_ip="2001:db8:5::1",
        dst_ip="2001:db8:5::2",
        flow_label=0xDEAD1,
        udp_src_port=10005,
        udp_dst_port=20005,
        udp_payload=b"ALL_3",
        hbh_options=(
            altmark_option(
                flowmonid=0xABCDE,
                loss=1,
                delay=1
            ) +
            ioam_pot_option(
                namespace_id=0x0030,
                packet_id=0x0000000000000005,
                cumulative=0xA1A2A3A4A5A6A7A8
            )
        ),
        dst_options=pdm_option(
            psn_this=100,
            psn_last=99,
            delta_last_recv=40,
            delta_last_sent=80,
            scale_recv=0,
            scale_sent=1
        ),
        src_mac=b"\x02\x00\x00\x00\x00\x05",
        dst_mac=b"\x02\x00\x00\x00\x01\x05"
    ))

    output_file = "pacotes_teste.pcap"
    write_pcap(output_file, packets)

    print(f"Arquivo gerado: {output_file}")
    print(f"Total de pacotes: {len(packets)}")

if __name__ == "__main__":
    main()
