

#ifndef REPLACEPACKET_H_H_H
#define REPLACEPACKET_H_H_H


#include "../attacker/include\\pcap.h"
#include "../attacker/include\\pcap\\pcap.h"
#include "Packet.h"

class AttackPacket {
public:
	static int ReplacePacket(pcap_t * pcapT, const char * lppacket, int packetsize, const char * lpsenddata, int sendsize,
		char * ip, int type, LPPPPOEHEADER pppoe);

	static int ReplaceIPV6Packet(pcap_t * pcapT, const char * lppacket, int packetsize, const char * lpsenddata, int sendsize,
		char * ip, int type, LPPPPOEHEADER pppoe);
};


#endif