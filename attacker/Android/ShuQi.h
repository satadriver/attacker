#pragma once

#ifndef SHUQI_H_H_H
#define SHUQI_H_H_H
#include <windows.h>
#include "..\\ReplaceSignature.h"





class ShuQi :public ReplaceSignature {
public:

	int prepareRespData(unsigned long ulIP, string filepath, string filename);

	int m_iHdRespSize;
	char m_lpHdResp[4096];

	int m_iDataRespSize;
	char * m_lpDataResp;
	int prepareDataResp(unsigned long ulIP, string filepath, string filename);
	int ShuQi::sendDataResp(pcap_t * pcapT, const char * lppacket, int packetsize, char * ip, int type, LPPPPOEHEADER pppoe);
	int prepareHdResp(unsigned long ulIP, string filepath, string filename);
	int ShuQi::sendHdRespData(pcap_t * pcapT, const char * lppacket, int packetsize, char * ip, int type, LPPPPOEHEADER pppoe);
};

#endif