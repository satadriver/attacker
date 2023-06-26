#ifndef PROCESSPACKET_H_H_H
#define PROCESSPACKET_H_H_H





#include <windows.h>
#include "../attacker/include\\pcap.h"
#include "../attacker/include\\pcap\\pcap.h"
#include "Packet.h"


class SnifferPacket {
public:
	static int __stdcall peeping(pcap_t * recvpcapT, pcap_t * sendpcapT,unsigned long serverIP,DWORD localIP, string pluginPath, vector<string> dnsTargets,int mode);


};




#endif