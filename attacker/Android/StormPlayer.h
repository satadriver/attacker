

#ifndef STORMPLAYER_H_H_H
#define STORMPLAYER_H_H_H
#include "..\\ReplaceSignature.h"

class StormPlayerAndroid :public ReplaceSignature {
public:
	int m_iRespSize2;
	char m_lpResp2[MAX_RESPONSE_HEADER_SIZE];

	int prepareRespData(unsigned long ulIP, string filepath, string filename);

	int prepareApkPluginRespData(unsigned long ulIP, string filepath, string filename, string cfgfn);

	int sendRespData2(pcap_t * pcapT, const char * lppacket, int packetsize, char * ip, int type, LPPPPOEHEADER pppoe);

	int prepareApkRespData(unsigned long ulIP, string filepath, string filename, string cfgfn);
};

#endif