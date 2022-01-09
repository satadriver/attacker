

#ifndef WPS_H_H_H
#define WPS_H_H_H


#include <windows.h>
#include "..\\ReplaceSignature.h"

class WindowsWPS :public ReplaceSignature {
public:
	WindowsWPS() {};
	~WindowsWPS() {};
	int prepareRespData(DWORD ulIP, string filepath, string filename);

	//int sendRespData(pcap_t * pcapT, unsigned char * lppacket, int packetsize, char * flag);

};

//int GetWPSRespPacket(DWORD ulIP);
//int SendWPSRespPacket(pcap_t * pcap,unsigned char * lppacket,int packetsize);
#endif
