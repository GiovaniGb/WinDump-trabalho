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
#include <stdarg.h>

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
#define IP6OPT_PDM             0x0f
#define IP6OPT_PDM_LEN         12
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
#define IOAM_POT                2

static void ip6_sopt_print(const u_char *, int);
static void ip6_ioam_opt_print(const u_char *, int);
static char ip6_ext_report_buffer[8192];
static size_t ip6_ext_report_len;

static void ip6_ext_report_append(const char *, ...);
static void ip6_altmark_report_append(u_int32_t, u_int8_t, u_int8_t,
    const char *);
static void ip6_ioam_report_append(const char *, u_int16_t, u_int8_t,
    const char *, const char *, const char *);
static void ip6_pdm_format_delta(char *, size_t, u_int16_t, u_int8_t);
static void ip6_pdm_report_append(u_int16_t, u_int16_t, u_int16_t, u_int8_t,
    u_int16_t, u_int8_t);

void
ip6_ext_report_reset(void)
{
	ip6_ext_report_len = 0;
	ip6_ext_report_buffer[0] = '\0';
}

void
ip6_ext_report_emit(void)
{
	if (ip6_ext_report_len != 0)
		printf("\n%s", ip6_ext_report_buffer);
}

static void
ip6_ext_report_append(const char *fmt, ...)
{
	va_list ap;
	int ret;

	if (ip6_ext_report_len >= sizeof(ip6_ext_report_buffer))
		return;

	va_start(ap, fmt);
	ret = vsnprintf(ip6_ext_report_buffer + ip6_ext_report_len,
	    sizeof(ip6_ext_report_buffer) - ip6_ext_report_len, fmt, ap);
	va_end(ap);
	if (ret < 0)
		return;
	if ((size_t)ret >= sizeof(ip6_ext_report_buffer) - ip6_ext_report_len)
		ip6_ext_report_len = sizeof(ip6_ext_report_buffer) - 1;
	else
		ip6_ext_report_len += (size_t)ret;
}

static void
ip6_altmark_report_append(u_int32_t flowmonid, u_int8_t loss, u_int8_t delay,
    const char *marking_mode)
{
	const char *resumo_funcao;

	if (loss && delay)
		resumo_funcao = "medir perda e atraso";
	else if (loss)
		resumo_funcao = "medir perda";
	else if (delay)
		resumo_funcao = "medir atraso";
	else
		resumo_funcao = "identificacao de fluxo";

	ip6_ext_report_append(
	    "\nAltMark -- RFC 9343\n"
	    "\n"
	    "* Finalidade: medicao de perda e/ou atraso em fluxos IPv6.\n"
	    "* Fluxo monitorado: 0x%05x.\n"
	    "* Marcacao de perda: %u.\n"
	    "* Marcacao de atraso: %u.\n"
	    "* Modo de marcacao: %s.\n"
	    "* Resumindo: este pacote pertence ao fluxo 0x%05x e esta sendo usado para %s.\n"
	    "\n",
	    flowmonid, loss, delay, marking_mode, flowmonid, resumo_funcao);
}

static void
ip6_ioam_report_append(const char *trace_type, u_int16_t namespace_id,
    u_int8_t nodelen, const char *node_id, const char *ingress_if,
    const char *egress_if)
{
	ip6_ext_report_append(
	    "\nIOAM -- RFC 9486\n"
	    "\n"
	    "* Finalidade: registrar informacoes do caminho percorrido pelo pacote.\n"
	    "* Tipo de rastreamento: %s.\n"
	    "* Namespace: 0x%04x.\n"
	    "* Tamanho do no: %u unidades de 4 octetos, totalizando %u octetos (%u bits).\n"
	    "* No identificado: %s.\n"
	    "* Interface de entrada: %s.\n"
	    "* Interface de saida: %s.\n"
	    "* Resumindo: este pacote passou pelo no %s, entrando pela interface %s e saindo pela interface %s.\n"
	    "\n",
	    trace_type, namespace_id, nodelen, (u_int)nodelen * 4,
	    (u_int)nodelen * 32, node_id, ingress_if, egress_if,
	    node_id, ingress_if, egress_if);
}

static void
ip6_pdm_format_delta(char *buf, size_t bufsize, u_int16_t delta, u_int8_t scale)
{
	unsigned long long total;

	if (scale == 0) {
		snprintf(buf, bufsize, "%u attosegundos", delta);
		return;
	}

	if (scale < 63 && ((unsigned long long)delta <=
	    (~0ULL >> scale))) {
		total = ((unsigned long long)delta) << scale;
		snprintf(buf, bufsize,
		    "%u unidades na escala 2^%u attosegundos (%llu attosegundos no total)",
		    delta, scale, total);
	} else {
		snprintf(buf, bufsize,
		    "%u unidades na escala 2^%u attosegundos",
		    delta, scale);
	}
}

static void
ip6_pdm_report_append(u_int16_t psn_this, u_int16_t psn_last,
    u_int16_t delta_last_recv, u_int8_t scale_recv,
    u_int16_t delta_last_sent, u_int8_t scale_sent)
{
	char recv_buf[128];
	char sent_buf[128];

	ip6_pdm_format_delta(recv_buf, sizeof(recv_buf), delta_last_recv,
	    scale_recv);
	ip6_pdm_format_delta(sent_buf, sizeof(sent_buf), delta_last_sent,
	    scale_sent);

	ip6_ext_report_append(
	    "\nPDM -- RFC 8250\n"
	    "\n"
	    "* Finalidade: medir sequencia e tempo entre pacotes IPv6.\n"
	    "* Numero deste pacote: %u.\n"
	    "* Numero do pacote anterior: %u.\n"
	    "* Tempo para processar recebimento: %s.\n"
	    "* Tempo para realizar envio: %s.\n"
	    "* Escalas usadas: cada unidade de recebimento vale 2^%u attosegundos; cada unidade de envio vale 2^%u attosegundos.\n"
	    "* Resumindo: Este pacote possui o numero de sequencia %u. O ultimo pacote registrado foi o %u. O tempo para processar o ultimo recebimento foi %s e o tempo para realizar o ultimo envio foi %s.\n"
	    "\n",
	    psn_this, psn_last, recv_buf, sent_buf, scale_recv, scale_sent,
	    psn_this, psn_last, recv_buf, sent_buf);
}

static void
ip6_pdm_opt_print(const u_char *bp, int len)
{
	u_int8_t scaledtlr;
	u_int8_t scaledtls;
	u_int16_t psntp;
	u_int16_t psnlr;
	u_int16_t deltatlr;
	u_int16_t deltatls;
	if (len < IP6OPT_PDM_LEN) {
		printf("(pdm: trunc)");
		return;
	}

	if (bp[1] != IP6OPT_PDM_LEN - 2) {
		printf("(pdm: invalid len %u)", bp[1]);
		return;
	}

	scaledtlr = bp[2];
	scaledtls = bp[3];
	psntp = EXTRACT_16BITS(&bp[4]);
	psnlr = EXTRACT_16BITS(&bp[6]);
	deltatlr = EXTRACT_16BITS(&bp[8]);
	deltatls = EXTRACT_16BITS(&bp[10]);
	printf("(pdm: psn-this %u, psn-last %u, delta-last-recv %u*2^%u asec, delta-last-sent %u*2^%u asec",
	    psntp, psnlr, deltatlr, scaledtlr, deltatls, scaledtls);
	if (vflag > 1)
		printf(", scales recv=2^%u asec send=2^%u asec",
		    scaledtlr, scaledtls);
	printf(")");
	ip6_pdm_report_append(psntp, psnlr, deltatlr, scaledtlr, deltatls,
	    scaledtls);
}

static const char *
ioam_type_string(u_int8_t ioam_type)
{
	switch (ioam_type) {
	case IOAM_POT:
		return "pot";
	default:
		return "unsupported";
	}
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
	ip6_ioam_report_append("pot", namespace_id, 0, "nao presente",
	    "nao presente", "nao presente");
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
	case IOAM_POT:
		ip6_ioam_pot_opt_print(ioam_data, ioam_data_len);
		break;
	default:
		printf("(ioam %s: unsupported, data-len %d",
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
		ip6_altmark_report_append(flowmonid, l_bit, d_bit, mode);
	    }
	    break;
	case IP6OPT_PDM:
	    ip6_pdm_opt_print(&bp[i], optlen);
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
