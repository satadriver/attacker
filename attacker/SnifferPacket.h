#ifndef PROCESSPACKET_H_H_H
#define PROCESSPACKET_H_H_H





#include <windows.h>
#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"
#include "Packet.h"


class SnifferPacket {
public:
	static int __stdcall peeping(pcap_t * recvpcapT,unsigned long serverIP,DWORD localIP, string pluginPath,int mode);


};




#endif