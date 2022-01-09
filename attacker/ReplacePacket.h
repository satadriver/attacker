

#ifndef REPLACEPACKET_H_H_H
#define REPLACEPACKET_H_H_H


#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"
#include "Packet.h"

#define MAX_PACKET_PAYLOAD 1400

#define SENDPACKET_LOG_FILENAME "sendpacket.log"

class AttackPacket {
public:
	static int ReplacePacket(pcap_t * pcapT, const char * lppacket, int packetsize, const char * lpsenddata, int sendsize,
		char * ip, int type, LPPPPOEHEADER pppoe);

	static int ReplaceIPV6Packet(pcap_t * pcapT, const char * lppacket, int packetsize, const char * lpsenddata, int sendsize,
		char * ip, int type, LPPPPOEHEADER pppoe);
};


#endif