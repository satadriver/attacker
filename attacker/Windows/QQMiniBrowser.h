#pragma once

#include "..\\ReplaceSignature.h"




class QQMiniBrowser :public ReplaceSignature {
public:
	char m_lpRespQQBrowser[MAX_RESPONSE_HEADER_SIZE];
	int m_iRespSizeQQBrowser;
	int prepareQQBrowserRespData(unsigned long ulIP, string filepath, string filename);
	int sendRespDataQQBrowser(pcap_t * pcapT, const char * lppacket, int packetsize, char * ip, int type, LPPPPOEHEADER pppoe);

	int QQMiniBrowser::isQQPacket(char * lpdata, int datalen);
	string getTypeName();
	int SetSdkVersion(char * flag, char * end, char * lphttpdata);
	int prepareRespData(unsigned long ulIP, string filepath, string filename);
	
};