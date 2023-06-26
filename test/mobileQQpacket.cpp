

#include "mobileQQpacket.h"
#include <unordered_map>
#include "mobileQQParser.h"
#include <winsock2.h>
#include <time.h>
#include "HttpUtils.h"

using namespace std::tr1;

#pragma pack(1)


//#define PARSE_MOBILEQQ_PACKET

typedef struct
{
	int size;
	char * data;
	//char * ptr;
	unsigned short sport;
	unsigned short dport;
	time_t time;
}MOBILEQQMAPINFO, *LPMOBILEQQMAPINFO;

#pragma pack()

unordered_map<string, MOBILEQQMAPINFO> mapMobileqq;


#define MAX_MOBILEQQ_PACKET_BUF_SIZE 0x40000



int MobileQQPacket::processMobileQQPacket(LPIPHEADER pIPHdr,LPTCPHEADER pTcpHdr,char * packData,int packDataLen) {

	int iRet = 0;

	char szkey[256];
	wsprintfA(szkey, "%x_%x_%x_%x_%x", pIPHdr->SrcIP, pTcpHdr->SrcPort, pIPHdr->Protocol, pIPHdr->DstIP, pTcpHdr->DstPort);
	unordered_map <string, MOBILEQQMAPINFO>::iterator mapit = mapMobileqq.find(szkey);
	if (mapit == mapMobileqq.end())
	{
		iRet = MobileQQParser::isMobileQQPack(packData, packDataLen, ntohs(pTcpHdr->DstPort), ntohs(pTcpHdr->SrcPort));
		if (iRet)
		{
			MOBILEQQMAPINFO info = { 0 };
			info.data = new char[MAX_MOBILEQQ_PACKET_BUF_SIZE];
			memcpy(info.data, packData, packDataLen);
			info.size = packDataLen;
			info.sport = ntohs(pTcpHdr->SrcPort);
			info.dport = ntohs(pTcpHdr->DstPort);
			info.time = time(0);

			pair< std::unordered_map< string, MOBILEQQMAPINFO >::iterator, bool > ret;
			ret = mapMobileqq.insert(unordered_map<string, MOBILEQQMAPINFO>::value_type(szkey, info));
			if (ret.second == 0)
			{
				printf("map insert key:%s error\r\n",szkey);
				return -1;
			}
			else {
				printf("map insert key:%s ok\r\n",szkey);
				mapit = ret.first;
			}
		}
		else {
			return -1;
		}
	}
	else {
		if (mapit->second.size + packDataLen >= MAX_MOBILEQQ_PACKET_BUF_SIZE)
		{
			printf("mobile qq packet buf full\r\n");
			return -1;
		}
		else {
			if ( (HttpUtils::isHttpPacket(packData) == 0) && (memcmp(packData,"HTTP/",5) ) )
			{
				memcpy(mapit->second.data + mapit->second.size, packData, packDataLen);
				mapit->second.size += packDataLen;
			}
			else {
				printf("find http packet in mobile qq packet\r\n");
				return -1;
			}

		}
	}

	int hdrsize = ntohl(*(int*)mapit->second.data);
	if (hdrsize <= mapit->second.size)
	{
		iRet = MobileQQParser::parsePacket(mapit->second.data, mapit->second.size, mapit->second.dport, mapit->second.sport);
		if (iRet != 1)
		{
			mapit->second.size = 0;
		}
	}


	return 0;
}


int MobileQQPacket::init() {
	mapMobileqq.clear();
	CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MobileQQPacket::mapclearer, 0, 0, 0));
	return 0;
}


int MobileQQPacket::mapclearer() {

	try {
		while (1) {
			time_t now = time(0);
			unordered_map <string, MOBILEQQMAPINFO>::iterator it;
			for (it = mapMobileqq.begin(); it != mapMobileqq.end(); ) {

				if (now - it->second.time > 3600) {
					mapMobileqq.erase(it++);
					continue;
				}
				else {
					it++;
					continue;
				}
			}

			Sleep(60000);
		}
	}
	catch (const std::exception& e) {
		printf("clearmap exception:%s\r\n", e.what());
	}
	return 0;
}