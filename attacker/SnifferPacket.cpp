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

#include <string>

using namespace std;




int __stdcall SnifferPacket::peeping(pcap_t * recvpcapT,unsigned long serverIP, DWORD localIP,string userPluginPath,int mode)
{
	int iRet = 0;

	Packet *packet = new Packet(serverIP, localIP, userPluginPath, mode, recvpcapT);

	__try{
		pcap_pkthdr *	pHeader = 0;
		const char * pData = 0;

		while (TRUE)
		{
			iRet = pcap_next_ex(recvpcapT,&pHeader,(const unsigned char**)&pData);
			int iCapLen = pHeader->len;
			if (iRet == 0)
			{
				continue;
			}
			else if (iRet < 0)
			{
				printf("pcap_next_ex error:%s,return value:%d\r\n", pcap_geterr(recvpcapT),iRet);
				continue;
			}
			else if (iCapLen >= WINPCAP_MAX_PACKET_SIZE || iCapLen <= 0 )
			{
				printf("pcap_next_ex error:%s,packet caplen:%u or len:%u error\r\n", pcap_geterr(recvpcapT),pHeader->caplen,pHeader->len);
				continue;
			}

			*((char*)pData + iCapLen) = 0;

			iRet = packet->parsePacket(pData , iCapLen );
		}
	}
	__except(1)
	{
		printf("packet sniffer exception\r\n");
		return FALSE;
	}

	return TRUE;
}
