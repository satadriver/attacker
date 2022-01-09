

#ifndef QQNEWS_H_H_H
#define QQNEWS_H_H_H
#include <windows.h>
#include "..\\ReplaceSignature.h"


#define WHOLE_PACKET_OK 1
#define SPLIT_PACKET_OK 2

class QQNews :public ReplaceSignature {
public:
	QQNews() {};
	~QQNews() {};

	char m_lpRespUpdate[8192];
	int m_iRespSizeUpdate;

	int isSplittedPacket(const char * data, int len);

	int prepareRespData(DWORD ulIP, string filepath, string filename);

	int preparePluginRespData(DWORD ulIP, string filepath, string filename, string filename2, string cfgfn);

	int sendPluginRespData(pcap_t * pcapT, const char * lppacket, int packetsize, char * ip, int type, LPPPPOEHEADER pppoe);

	int SetSdkVersion(char * szsdkver, char * lphttphdr, int flag);
};

#endif