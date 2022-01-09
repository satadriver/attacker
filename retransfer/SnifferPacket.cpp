
#include <vector>
#include <string>
#include <iostream>
#include "Public.h"
#include "Packet.h"
#include "SnifferPacket.h"



#include "HttpUtils.h"
#include "checksum.h"

#include "winpcap.h"
#include "initor.h"

#include <unordered_map>
#include <vector>
#include <map>

#include "Packet.h"


using namespace  std;
using namespace std::tr1;


#define WINPCAP_MAX_PACKET_SIZE 0x10000
#define MAX_URL_SIZE 4096

#define HTTPMETHOD_GET		1
#define HTTPMETHOD_POST		2
#define HTTPMETHOD_PUT		3
#define HTTPMETHOD_HEAD		4








int __stdcall SnifferPacket::peeping(pcap_t * recvpcapT,pcap_t * sendpcapT,unsigned long serverIP, DWORD localIP,string userPluginPath,vector<string> dnsTargets,int mode)
{
	int iRet = 0;

	iRet = Packet::init(serverIP, localIP, userPluginPath, dnsTargets,mode,sendpcapT);

	try{
		pcap_pkthdr *		pHeader = 0;
		const char * pData = 0;

		//LPHEADER8021Q p8021q = 0;
		//LPHEADER8021Q p8021q2 = 0;

		while (TRUE)
		{
			iRet = pcap_next_ex(recvpcapT,&pHeader,(const unsigned char**)&pData);
			if (iRet == 0)
			{
				//Sleep(1);
				continue;
			}else if (iRet < 0)
			{
				//char errorbuf[1024];
				//pcap_perror(recvpcapT,errorbuf);
				printf("pcap_next_ex error:%s,return value:%d\r\n", pcap_geterr(recvpcapT),iRet);
				continue;
			}
			//if (pHeader->len >= WINPCAP_MAX_PACKET_SIZE || pHeader->len <= 0)
			else if (/*(pHeader->caplen >= WINPCAP_MAX_PACKET_SIZE || pHeader->caplen <= 0) || */
				(pHeader->len >= WINPCAP_MAX_PACKET_SIZE || pHeader->len <= 0) )
			{
				//char errorbuf[1024];
				//pcap_perror(recvpcapT, errorbuf);
				printf("pcap_next_ex error:%s,packet caplen:%u or len:%u error\r\n", pcap_geterr(recvpcapT),pHeader->caplen,pHeader->len);
				continue;
			}

			//len是实际抓到的数据长度,比如tcp握手包如果实际长度小于60,len是实际长度，caplen最小是60
			int iCapLen = pHeader->len;
			*((char*)pData + iCapLen) = 0;

			int packSize = 0;
			do 
			{
				iRet = Packet::parsePacket(pData + packSize, iCapLen - packSize);
				if ( iRet >= 60)
				{
					packSize += iRet;
					if (packSize != iCapLen)
					{
						printf("multi packet\r\n");
					}
				}
				else {
					break;
				}

			} while (packSize < iCapLen);
		}
	}
	catch(...)
	{
		printf("packet sniffer exception\r\n");
		//getchar();
		return FALSE;
	}

	return TRUE;
}
