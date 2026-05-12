#pragma once

#include <winsock2.h>
#include "Packet.h"
#include "attacker.h"
#include "attack.h"
#include "PacketProc.h"
#include "DnsUtils/dnsUtils.h"
#include "utils/checksum.h"
#include "informer.h"
#include "SSL/sslPublic.h"

#pragma pack(1)

struct TRANSFER_ADDRESS {

	unsigned char tag;

	DWORD ip;

	WORD port;

	unsigned char macaddr[MAC_ADDRESS_SIZE];

	MACHEADER mac;

	//TRANSFER_ADDRESS(MACHEADER m, DWORD i, WORD p) :mac(m), ip(i), port(p) {}

};

#pragma pack()

int transferPacket(pcap_t* mPcapt, LPMACHEADER pMac, LPPPPOEHEADER pppoe, IPHEADER* pIPV4Hdr, TCPHEADER* tcphdr,
	DWORD gLocalIP, const char* pData, int realPackSize,int direction);