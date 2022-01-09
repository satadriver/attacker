#pragma once

#ifndef HttpPartial_H_H_H
#define HttpPartial_H_H_H



#include <windows.h>
#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"

#include "ReplacePacket.h"
#include "attacker.h"
#include "openssl/md5.h"
#include <iostream>
#include "ssl/sslPublic.h"


using namespace std;

// extern char * lpQQMiniBrowserData ;
// extern int iQQMiniBrowserDataSize ;
// 
// extern char * lpQQnewsData ;
// extern int iQQnewsDataSize;
// 
// extern char * lpIqiyiVideoData ;
// extern int iIqiyiDataSize ;
// 
// extern char * lpIqiyiPcUpdateData;
// extern int iIqiyiPcUpdateSize;
// 
// extern char * lpOppoBrowserData;
// extern int iOppoBrowserDataSize;

extern char * lpYoukuData ;
extern int iYoukudateSize ;




class HttpPartial {
public:
	char * m_lpfiledata;
	int m_filesize;

	int sendReplacePartial(pcap_t * pcapT, char * lppacket, int packetsize, int start, int end, char * ip, int type, LPPPPOEHEADER pppoe);
	int PrepareReplacePartial(string filename);

	static int AliCdnPartialFile(string fn, SOCKET s, int begin, int end);
	static int HttpPartial::AliCdnPartialFile(string fn, LPSSLPROXYPARAM ssl, int begin, int end);

	static int sendPartialFile(string fn, SOCKET s, int begin, int end, string formatstr);
	static int HttpPartial::sendPartFileWithoutHdr(string fn, SOCKET s, int begin, int end);
	static int HttpPartial::sendPartFileWithoutHdr(string fn, LPSSLPROXYPARAM ssl, int begin, int end);
};

#endif



