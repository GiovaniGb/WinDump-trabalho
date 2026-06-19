/*
 * Copyright (C) 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef lint
static const char rcsid[] _U_ =
     "@(#) $Header: /tcpdump/master/tcpdump/print-ip6opts.c,v 1.17.2.1 2005/04/20 22:19:06 guy Exp $";
#endif

#ifdef INET6
#include <tcpdump-stdinc.h>

#include <stdio.h>

#include "ip6.h"

#include "interface.h"
#include "addrtoname.h"
#include "extract.h"

/* items outside of rfc2292bis */
#ifndef IP6OPT_MINLEN
#define IP6OPT_MINLEN	2
#endif
#ifndef IP6OPT_RTALERT_LEN
#define IP6OPT_RTALERT_LEN	4
#endif
#ifndef IP6OPT_JUMBO_LEN
#define IP6OPT_JUMBO_LEN	6
#endif
#define IP6OPT_IOAM            0x11
#define IP6OPT_IOAM_ALT        0x31
#define IP6OPT_ALTMARK        0x12
#define IP6OPT_ALTMARK_LEN    6
#define IP6OPT_HOMEADDR_MINLEN 18
#define IP6OPT_BU_MINLEN       10
#define IP6OPT_BA_MINLEN       13
#define IP6OPT_BR_MINLEN        2
#define IP6SOPT_UI            0x2
#define IP6SOPT_UI_MINLEN       4
#define IP6SOPT_ALTCOA        0x3
#define IP6SOPT_ALTCOA_MINLEN  18
#define IP6SOPT_AUTH          0x4
#define IP6SOPT_AUTH_MINLEN     6
#define IOAM_TRACE_PREALLOC     0
#define IOAM_TRACE_INCREMENTAL  1
#define IOAM_POT                2
#define IOAM_E2E                3
#define IOAM_DEX                4

static void ip6_sopt_print(const u_char *, int);
static void ip6_ioam_opt_print(const u_char *, int);

static void
ip6_ioam_print_bit_names(u_int32_t value, const char *const *names, int count)
{
	int bit;
	int first = 1;

	for (bit = 0; bit < count; bit++) {
		u_int32_t mask = 1U << (count - 1 - bit);

		if ((value & mask) == 0 || names[bit] == NULL)
			continue;
		if (first) {
			printf(" [");
			first = 0;
		} else
			printf(", ");
		printf("%s", names[bit]);
	}
	if (!first)
		printf("]");
}

static const char *
ioam_type_string(u_int8_t ioam_type)
{
	switch (ioam_type) {
	case IOAM_TRACE_PREALLOC:
		return "prealloc-trace";
	case IOAM_TRACE_INCREMENTAL:
		return "incremental-trace";
	case IOAM_POT:
		return "pot";
	case IOAM_E2E:
		return "e2e";
	case IOAM_DEX:
		return "dex";
	default:
		return "unknown";
	}
}

static const char *const ioam_trace_type_names[24] = {
	"hoplim+nodeid-short",
	"ifid-short",
	"ts-secs",
	"ts-frac",
	"transit-delay",
	"ns-data-short",
	"queue-depth",
	"checksum-complement",
	"hoplim+nodeid-wide",
	"ifid-wide",
	"ns-data-wide",
	"buffer-occupancy",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	"opaque-state-snapshot",
	"reserved"
};

static const char *const ioam_e2e_type_names[16] = {
	"seq64",
	"seq32",
	"ts-secs",
	"ts-frac",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

static void
ip6_ioam_trace_opt_print(const u_char *bp, int len, const char *trace_name)
{
	u_int16_t namespace_id;
	u_int16_t hdr_fields;
	u_int8_t node_len;
	u_int8_t flags;
	u_int8_t remaining_len;
	u_int32_t trace_type;
	u_int8_t reserved;

	if (len < 8) {
		printf("(ioam %s: trunc)", trace_name);
		return;
	}

	namespace_id = EXTRACT_16BITS(&bp[0]);
	hdr_fields = EXTRACT_16BITS(&bp[2]);
	node_len = (u_int8_t)(hdr_fields >> 11);
	flags = (u_int8_t)((hdr_fields >> 7) & 0x0f);
	remaining_len = (u_int8_t)(hdr_fields & 0x7f);
	trace_type = EXTRACT_24BITS(&bp[4]);
	reserved = bp[7];

	printf("(ioam %s: ns 0x%04x, nodelen %u, remlen %u, flags 0x%x, trace-type 0x%06x",
	    trace_name, namespace_id, node_len, remaining_len, flags, trace_type);
	ip6_ioam_print_bit_names(trace_type, ioam_trace_type_names, 24);
	if (flags & 0x8)
		printf(", overflow");
	if (reserved)
		printf(", reserved=0x%02x", reserved);
	printf(")");
}

static void
ip6_ioam_pot_opt_print(const u_char *bp, int len)
{
	u_int16_t namespace_id;
	u_int8_t pot_type;
	u_int8_t pot_flags;

	if (len < 4) {
		printf("(ioam pot: trunc)");
		return;
	}

	namespace_id = EXTRACT_16BITS(&bp[0]);
	pot_type = bp[2];
	pot_flags = bp[3];

	printf("(ioam pot: ns 0x%04x, type %u", namespace_id, pot_type);
	if (pot_flags)
		printf(", flags 0x%02x", pot_flags);

	if (pot_type == 0 && len >= 20) {
		printf(", pktid 0x%08x%08x, cumulative 0x%08x%08x",
		    EXTRACT_32BITS(&bp[4]), EXTRACT_32BITS(&bp[8]),
		    EXTRACT_32BITS(&bp[12]), EXTRACT_32BITS(&bp[16]));
	} else if (len > 4) {
		printf(", data-len %d", len - 4);
	}
	printf(")");
}

static void
ip6_ioam_e2e_opt_print(const u_char *bp, int len)
{
	u_int16_t namespace_id;
	u_int16_t e2e_type;

	if (len < 4) {
		printf("(ioam e2e: trunc)");
		return;
	}

	namespace_id = EXTRACT_16BITS(&bp[0]);
	e2e_type = EXTRACT_16BITS(&bp[2]);
	printf("(ioam e2e: ns 0x%04x, type 0x%04x", namespace_id, e2e_type);
	ip6_ioam_print_bit_names(e2e_type, ioam_e2e_type_names, 16);
	if (len > 4)
		printf(", data-len %d", len - 4);
	printf(")");
}

static void
ip6_ioam_dex_opt_print(const u_char *bp, int len)
{
	u_int16_t namespace_id;
	u_int8_t flags;
	u_int8_t ext_flags;
	u_int32_t trace_type;
	u_int8_t reserved;
	int offset;

	if (len < 8) {
		printf("(ioam dex: trunc)");
		return;
	}

	namespace_id = EXTRACT_16BITS(&bp[0]);
	flags = bp[2];
	ext_flags = bp[3];
	trace_type = EXTRACT_24BITS(&bp[4]);
	reserved = bp[7];
	offset = 8;

	printf("(ioam dex: ns 0x%04x, flags 0x%02x, ext-flags 0x%02x, trace-type 0x%06x",
	    namespace_id, flags, ext_flags, trace_type);
	if (reserved)
		printf(", reserved=0x%02x", reserved);

	if (ext_flags & 0x80) {
		if (len < offset + 4) {
			printf(", flow-id: trunc)");
			return;
		}
		printf(", flow-id 0x%08x", EXTRACT_32BITS(&bp[offset]));
		offset += 4;
	}
	if (ext_flags & 0x40) {
		if (len < offset + 4) {
			printf(", seq: trunc)");
			return;
		}
		printf(", seq %u", EXTRACT_32BITS(&bp[offset]));
		offset += 4;
	}
	if (len > offset)
		printf(", extra-bytes %d", len - offset);
	printf(")");
}

static void
ip6_ioam_opt_print(const u_char *bp, int len)
{
	u_int8_t option_type;
	u_int8_t option_data_len;
	u_int8_t ioam_reserved;
	u_int8_t ioam_type;
	const u_char *ioam_data;
	int ioam_data_len;

	if (len < 4) {
		printf("(ioam: trunc)");
		return;
	}

	option_type = bp[0];
	option_data_len = bp[1];
	ioam_reserved = bp[2];
	ioam_type = bp[3];
	ioam_data = &bp[4];
	ioam_data_len = len - 4;

	if (option_data_len != len - 2) {
		printf("(ioam: invalid len %u)", option_data_len);
		return;
	}

	switch (ioam_type) {
	case IOAM_TRACE_PREALLOC:
		ip6_ioam_trace_opt_print(ioam_data, ioam_data_len, "prealloc-trace");
		break;
	case IOAM_TRACE_INCREMENTAL:
		ip6_ioam_trace_opt_print(ioam_data, ioam_data_len,
		    "incremental-trace");
		break;
	case IOAM_POT:
		ip6_ioam_pot_opt_print(ioam_data, ioam_data_len);
		break;
	case IOAM_E2E:
		ip6_ioam_e2e_opt_print(ioam_data, ioam_data_len);
		break;
	case IOAM_DEX:
		ip6_ioam_dex_opt_print(ioam_data, ioam_data_len);
		break;
	default:
		printf("(ioam %s: data-len %d",
		    ioam_type_string(ioam_type), ioam_data_len);
		if (ioam_reserved)
			printf(", ioam-reserved=0x%02x", ioam_reserved);
		printf(", carrier 0x%02x)", option_type);
		break;
	}
}

static void
ip6_sopt_print(const u_char *bp, int len)
{
    int i;
    int optlen;

    for (i = 0; i < len; i += optlen) {
	if (bp[i] == IP6OPT_PAD1)
	    optlen = 1;
	else {
	    if (i + 1 < len)
		optlen = bp[i + 1] + 2;
	    else
		goto trunc;
	}
	if (i + optlen > len)
	    goto trunc;

	switch (bp[i]) {
	case IP6OPT_PAD1:
            printf(", pad1");
	    break;
	case IP6OPT_PADN:
	    if (len - i < IP6OPT_MINLEN) {
		printf(", padn: trunc");
		goto trunc;
	    }
            printf(", padn");
	    break;
        case IP6SOPT_UI:
             if (len - i < IP6SOPT_UI_MINLEN) {
		printf(", ui: trunc");
		goto trunc;
	    }
            printf(", ui: 0x%04x ", EXTRACT_16BITS(&bp[i + 2]));
	    break;
        case IP6SOPT_ALTCOA:
             if (len - i < IP6SOPT_ALTCOA_MINLEN) {
		printf(", altcoa: trunc");
		goto trunc;
	    }
            printf(", alt-CoA: %s", ip6addr_string(&bp[i+2]));
	    break;
        case IP6SOPT_AUTH:
             if (len - i < IP6SOPT_AUTH_MINLEN) {
		printf(", auth: trunc");
		goto trunc;
	    }
            printf(", auth spi: 0x%08x", EXTRACT_32BITS(&bp[i + 2]));
	    break;
	default:
	    if (len - i < IP6OPT_MINLEN) {
		printf(", sopt_type %d: trunc)", bp[i]);
		goto trunc;
	    }
	    printf(", sopt_type 0x%02x: len=%d", bp[i], bp[i + 1]);
	    break;
	}
    }
    return;

trunc:
    printf("[trunc] ");
}

void
ip6_opt_print(const u_char *bp, int len)
{
    int i;
    int optlen = 0;

    for (i = 0; i < len; i += optlen) {
	if (bp[i] == IP6OPT_PAD1)
	    optlen = 1;
	else {
	    if (i + 1 < len)
		optlen = bp[i + 1] + 2;
	    else
		goto trunc;
	}
	if (i + optlen > len)
	    goto trunc;

	switch (bp[i]) {
	case IP6OPT_PAD1:
            printf("(pad1)");
	    break;
	case IP6OPT_PADN:
	    if (len - i < IP6OPT_MINLEN) {
		printf("(padn: trunc)");
		goto trunc;
	    }
            printf("(padn)");
	    break;
	case IP6OPT_ROUTER_ALERT:
	    if (len - i < IP6OPT_RTALERT_LEN) {
		printf("(rtalert: trunc)");
		goto trunc;
	    }
	    if (bp[i + 1] != IP6OPT_RTALERT_LEN - 2) {
		printf("(rtalert: invalid len %d)", bp[i + 1]);
		goto trunc;
	    }
	    printf("(rtalert: 0x%04x) ", EXTRACT_16BITS(&bp[i + 2]));
	    break;
	case IP6OPT_JUMBO:
	    if (len - i < IP6OPT_JUMBO_LEN) {
		printf("(jumbo: trunc)");
		goto trunc;
	    }
	    if (bp[i + 1] != IP6OPT_JUMBO_LEN - 2) {
		printf("(jumbo: invalid len %d)", bp[i + 1]);
		goto trunc;
	    }
	    printf("(jumbo: %u) ", EXTRACT_32BITS(&bp[i + 2]));
	    break;
	case IP6OPT_ALTMARK:
	    if (len - i < IP6OPT_ALTMARK_LEN) {
		printf("(altmark: trunc)");
		goto trunc;
	    }
	    if (bp[i + 1] != IP6OPT_ALTMARK_LEN - 2) {
		printf("(altmark: invalid len %d)", bp[i + 1]);
		goto trunc;
	    }
	    {
		u_int32_t altmark;
		u_int32_t flowmonid;
		u_int8_t l_bit;
		u_int8_t d_bit;
		u_int16_t reserved;
		const char *mode;

		altmark = EXTRACT_32BITS(&bp[i + 2]);
		flowmonid = altmark >> 12;
		l_bit = (altmark >> 11) & 0x01;
		d_bit = (altmark >> 10) & 0x01;
		reserved = altmark & 0x03ff;
		mode = d_bit ? "double-mark" : "single-mark";

		printf("(altmark: flowmonid 0x%05x, loss=%u, delay=%u, %s",
		    flowmonid, l_bit, d_bit, mode);
		if (reserved)
		    printf(", reserved=0x%03x", reserved);
		printf(")");
	    }
	    break;
	case IP6OPT_IOAM:
	case IP6OPT_IOAM_ALT:
	    ip6_ioam_opt_print(&bp[i], optlen);
	    break;
        case IP6OPT_HOME_ADDRESS:
	    if (len - i < IP6OPT_HOMEADDR_MINLEN) {
		printf("(homeaddr: trunc)");
		goto trunc;
	    }
	    if (bp[i + 1] < IP6OPT_HOMEADDR_MINLEN - 2) {
		printf("(homeaddr: invalid len %d)", bp[i + 1]);
		goto trunc;
	    }
	    printf("(homeaddr: %s", ip6addr_string(&bp[i + 2]));
            if (bp[i + 1] > IP6OPT_HOMEADDR_MINLEN - 2) {
		ip6_sopt_print(&bp[i + IP6OPT_HOMEADDR_MINLEN],
		    (optlen - IP6OPT_HOMEADDR_MINLEN));
	    }
            printf(")");
	    break;
        case IP6OPT_BINDING_UPDATE:
	    if (len - i < IP6OPT_BU_MINLEN) {
		printf("(bu: trunc)");
		goto trunc;
	    }
	    if (bp[i + 1] < IP6OPT_BU_MINLEN - 2) {
		printf("(bu: invalid len %d)", bp[i + 1]);
		goto trunc;
	    }
	    printf("(bu: ");
	    if (bp[i + 2] & 0x80)
		    printf("A");
	    if (bp[i + 2] & 0x40)
		    printf("H");
	    if (bp[i + 2] & 0x20)
		    printf("S");
	    if (bp[i + 2] & 0x10)
		    printf("D");
	    if ((bp[i + 2] & 0x0f) || bp[i + 3] || bp[i + 4])
		    printf("res");
	    printf(", sequence: %u", bp[i + 5]);
	    printf(", lifetime: %u", EXTRACT_32BITS(&bp[i + 6]));

	    if (bp[i + 1] > IP6OPT_BU_MINLEN - 2) {
		ip6_sopt_print(&bp[i + IP6OPT_BU_MINLEN],
		    (optlen - IP6OPT_BU_MINLEN));
	    }
	    printf(")");
	    break;
	case IP6OPT_BINDING_ACK:
	    if (len - i < IP6OPT_BA_MINLEN) {
		printf("(ba: trunc)");
		goto trunc;
	    }
	    if (bp[i + 1] < IP6OPT_BA_MINLEN - 2) {
		printf("(ba: invalid len %d)", bp[i + 1]);
		goto trunc;
	    }
	    printf("(ba: ");
	    printf("status: %u", bp[i + 2]);
	    if (bp[i + 3])
		    printf("res");
	    printf(", sequence: %u", bp[i + 4]);
	    printf(", lifetime: %u", EXTRACT_32BITS(&bp[i + 5]));
	    printf(", refresh: %u", EXTRACT_32BITS(&bp[i + 9]));

	    if (bp[i + 1] > IP6OPT_BA_MINLEN - 2) {
		ip6_sopt_print(&bp[i + IP6OPT_BA_MINLEN],
		    (optlen - IP6OPT_BA_MINLEN));
	    }
            printf(")");
	    break;
        case IP6OPT_BINDING_REQ:
	    if (len - i < IP6OPT_BR_MINLEN) {
		printf("(br: trunc)");
		goto trunc;
	    }
            printf("(br");
            if (bp[i + 1] > IP6OPT_BR_MINLEN - 2) {
		ip6_sopt_print(&bp[i + IP6OPT_BR_MINLEN],
		    (optlen - IP6OPT_BR_MINLEN));
	    }
            printf(")");
	    break;
	default:
	    if (len - i < IP6OPT_MINLEN) {
		printf("(type %d: trunc)", bp[i]);
		goto trunc;
	    }
	    printf("(opt_type 0x%02x: len=%d) ", bp[i], bp[i + 1]);
	    break;
	}
    }

#if 0
end:
#endif
    return;

trunc:
    printf("[trunc] ");
}

int
hbhopt_print(register const u_char *bp)
{
    const struct ip6_hbh *dp = (struct ip6_hbh *)bp;
    int hbhlen = 0;

    TCHECK(dp->ip6h_len);
    hbhlen = (int)((dp->ip6h_len + 1) << 3);
    TCHECK2(*dp, hbhlen);
    printf("HBH ");
    if (vflag)
	ip6_opt_print((const u_char *)dp + sizeof(*dp), hbhlen - sizeof(*dp));

    return(hbhlen);

  trunc:
    fputs("[|HBH]", stdout);
    return(-1);
}

int
dstopt_print(register const u_char *bp)
{
    const struct ip6_dest *dp = (struct ip6_dest *)bp;
    int dstoptlen = 0;

    TCHECK(dp->ip6d_len);
    dstoptlen = (int)((dp->ip6d_len + 1) << 3);
    TCHECK2(*dp, dstoptlen);
    printf("DSTOPT ");
    if (vflag) {
	ip6_opt_print((const u_char *)dp + sizeof(*dp),
	    dstoptlen - sizeof(*dp));
    }

    return(dstoptlen);

  trunc:
    fputs("[|DSTOPT]", stdout);
    return(-1);
}
#endif /* INET6 */
