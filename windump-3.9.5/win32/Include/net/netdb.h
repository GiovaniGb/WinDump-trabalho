/*
 * Compatibility shim for legacy WinDump sources that expect the
 * old WinPcap-provided <net/netdb.h> header on Windows.
 */
#ifndef WINDUMP_WIN32_NET_NETDB_H
#define WINDUMP_WIN32_NET_NETDB_H

#include <winsock2.h>
#include <ws2tcpip.h>

#endif
