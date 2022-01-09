#pragma once


#ifndef ZTEPLUGIN_H_H_H
#define ZTEPLUGIN_H_H_H

#include "..\\ReplaceSignature.h"
#include "../Packet.h"

class ZTEPluginUpdate :public ReplaceSignature {
public:
	int m_iRespSize2;
	char m_lpResp2[MAX_RESPONSE_HEADER_SIZE];

	int prepareRespData(unsigned long ulIP, string filepath, string filename);
	int prepareRespData2(unsigned long ulIP, string filepath, string filename);

	int sendRespData2(pcap_t * pcapT, const char * lppacket, int packetsize, char * ip, int type, LPPPPOEHEADER pppoe);
};
#endif