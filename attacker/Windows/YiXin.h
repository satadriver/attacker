#pragma once

#ifndef YIXIN_H_H_H
#define YIXIN_H_H_H
#include <windows.h>
#include "..\\ReplaceSignature.h"

class YiXin :public ReplaceSignature {
public:
	YiXin() {};
	~YiXin() {};
	int prepareRespData(DWORD ulIP, string filepath, string filename);

	//int sendRespData(pcap_t * pcapT, unsigned char * lppacket, int packetsize, char * flag);


};

#endif
