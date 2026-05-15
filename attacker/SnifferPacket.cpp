#include <windows.h>
#include <vector>
#include <string>
#include <iostream>
#include "Public.h"
#include "Packet.h"
#include "ReplaceNetFile.h"
#include "SnifferPacket.h"
#include "attack.h"
#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"
#include "HttpPartial.h"
#include "HttpUtils.h"
#include "utils/checksum.h"
#include "dnsutils/dnsUtils.h"
#include "winpcap.h"
#include <unordered_map>
#include <vector>
#include <map>
#include "informer.h"
#include "attacker.h"
#include "Packet.h"
#include <Shlobj.h>
#include "PacketProc.h"
#include "Utils/Tools.h"
#include <string>

using namespace std;


extern "C" void clog( const char* format, ...);

int __stdcall SnifferPacket::peeping(pcap_t * pcap,unsigned long serverIP, DWORD localIP,string userPluginPath,int mode)
{
	int iRet = 0;

	Packet *packet = new Packet(serverIP, localIP, userPluginPath, mode, pcap);

	__try{
		pcap_pkthdr *	pHeader = 0;
		const char * pData = 0;

		while (TRUE)
		{
			iRet = pcap_next_ex(pcap,&pHeader,(const unsigned char**)&pData);
			int iCapLen = pHeader->len;
			if (iRet == 0)
			{
				continue;
			}
			else if (iRet < 0)
			{
				colorlog(FOREGROUND_RED,"[%s %d] error:%s\r\n", __FUNCTION__, __LINE__, pcap_geterr(pcap));
				continue;
			}
			else if (iCapLen != pHeader->len || iCapLen >= WINPCAP_MAX_PACKET_SIZE || iCapLen <= 0 )
			{
				colorlog(FOREGROUND_RED,"[%s %d] error:%s caplen:%u len:%u\r\n", __FUNCTION__, __LINE__, pcap_geterr(pcap),pHeader->caplen,pHeader->len);
				continue;
			}

			*((char*)pData + iCapLen) = 0;

			iRet = packet->parsePacket(pData , iCapLen );
		}
	}
	__except(1)
	{
		log("%s %d exception\r\n",__FUNCTION__,__LINE__);
		return FALSE;
	}

	return TRUE;
}
