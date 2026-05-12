#pragma once



#include <winsock2.h>
#include "Packet.h"
#include "attacker.h"
#include "attack.h"
#include "PacketProc.h"
#include "DnsUtils/dnsUtils.h"
#include "utils/checksum.h"
#include "informer.h"

int udpPacket(pcap_t* mPcapt, LPMACHEADER pMac, LPPPPOEHEADER pppoe, IPHEADER* pIPV4Hdr,
	DNSANSWER* mDnsAnswer, int mMode, DWORD mLocalIP, const char* pData,int realSize, Informer* mInformer);


int udpPacketIPV6(pcap_t* mPcapt, LPMACHEADER pMac, LPPPPOEHEADER pppoe, IPV6HEADER* pIPV6,
	DNSANSWERIPV6* mDnsAnswerIPV6, DNSANSWER* mDnsAnswer, int mMode, DWORD mLocalIP,const char* pData, int realPackSize, Informer* mInformer);