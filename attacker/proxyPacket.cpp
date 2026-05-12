

#include <winsock2.h>
#include "Packet.h"
#include "attacker.h"
#include "attack.h"
#include "PacketProc.h"
#include "DnsUtils/dnsUtils.h"
#include "utils/checksum.h"
#include "informer.h"
#include "SSL/sslPublic.h"

#include <Windows.h>

#include <unordered_map>

#include <string>

#include "proxyPacket.h"



using namespace std;


unordered_map< __int64, TRANSFER_ADDRESS> g_map;


const unsigned char * g_routermac =(const unsigned char*) "\x70\x42\xd3\x7b\x02\xa4";

#define TRANSFER_IP_ADDRESS			0x8c6ea8c0
#define TRANSFER_MAC_ADDRESS		"\x90\xde\x80\x79\x88\x90"

pcap_t* g_pcaptLB = 0;

int init() {
	char errbuf[1024];
	g_pcaptLB = pcap_open_live("\\Device\\NPF_Loopback", 0x10000, 1, -1, errbuf);
	if (g_pcaptLB == NULL)
	{
		return 0;
	}
	return 0;
}


int transferPacket(pcap_t* mPcapt, LPMACHEADER pMac, LPPPPOEHEADER pppoe, IPHEADER* pIPV4Hdr, TCPHEADER * pTcpHdr,
	 DWORD mLocalIP, const char* pData, int realPackSize,int direction) {

	int iRet = 0;

	if (g_pcaptLB == 0) {
		init();
	}

	int iIpv4HdrLen = pIPV4Hdr->HeaderSize << 2;

	if (pppoe != 0)
	{

	}

	if (direction == 0) {

		if (pIPV4Hdr->DstIP == TRANSFER_IP_ADDRESS) {
			return 0;
		}

		__int64 key = pIPV4Hdr->SrcIP;
		key = key << 16;
		key += pTcpHdr->SrcPort;

		TRANSFER_ADDRESS ta ;
		
		if (pMac) {
			
			memcpy(ta.macaddr, pMac->DstMAC, MAC_ADDRESS_SIZE);

			memcpy(ta.mac.DstMAC, pMac->DstMAC, MAC_ADDRESS_SIZE);
			memcpy(ta.mac.SrcMAC, pMac->SrcMAC, MAC_ADDRESS_SIZE);
			ta.mac.Protocol = pMac->Protocol;
			ta.tag = 1;
		}
		else {
			ta.tag = 0;
		}
		ta.ip = pIPV4Hdr->DstIP;

		memcpy(pMac->DstMAC, TRANSFER_MAC_ADDRESS, MAC_ADDRESS_SIZE);

		pIPV4Hdr->DstIP = TRANSFER_IP_ADDRESS;
		pIPV4Hdr->DstIP = 0x0100007f;
		pIPV4Hdr->DstIP = mLocalIP;
		pIPV4Hdr->HeaderChksum = 0;
		pIPV4Hdr->HeaderChksum = Checksum::checksum((unsigned short*)pIPV4Hdr, iIpv4HdrLen);

		if (pMac) {
			//memcpy(pMac->DstMAC, "\x00\x00\x00\x00\x00\x00", MAC_ADDRESS_SIZE);
			//memcpy(pMac->SrcMAC, "\x00\x00\x00\x00\x00\x00", MAC_ADDRESS_SIZE);
			//pMac->Protocol = 0;

			*(DWORD*)(pData + 10) = AF_INET;
			iRet = pcap_sendpacket(g_pcaptLB, (const unsigned char*)pData + 10, realPackSize-10);

			//memcpy(pMac->DstMAC, gLocalMac, MAC_ADDRESS_SIZE);
			//memcpy(pMac->DstMAC, g_routermac, MAC_ADDRESS_SIZE);

			//iRet = pcap_sendpacket(mPcapt, (const unsigned char*)pData , realPackSize );
		}
		else {
			iRet = pcap_sendpacket(g_pcaptLB, (const unsigned char*)pData, realPackSize );
		}
		
		if (iRet == 0)
		{
			//Public::recorduser(pIPHdr->DstIP, dnsname);								
			//printf("process dns:%s,length:%u ok\r\n", dnsname, realPackSize + sizeof(DNSANSWER));
		}
		else {
			printf("pcap_sendpacket length:%u error:%u\r\n", realPackSize,GetLastError());
		}

		unordered_map<__int64, TRANSFER_ADDRESS>::iterator it = g_map.find(key);
		if (it == g_map.end()) {
			pair<unordered_map<__int64, TRANSFER_ADDRESS>::iterator,bool> res= g_map.insert(pair<__int64, TRANSFER_ADDRESS>(key, ta));
			if (res.second) {
				//printf("hello\r\n");
			}
		}
		else {
			if (it->second.ip != ta.ip) {
				it->second.ip = ta.ip;
				memcpy(it->second.mac.DstMAC, ta.mac.DstMAC, MAC_ADDRESS_SIZE);
				memcpy(it->second.mac.SrcMAC, ta.mac.SrcMAC, MAC_ADDRESS_SIZE);
				it->second.mac.Protocol = ta.mac.Protocol;
			}
		}
	}
	else {
		if (pIPV4Hdr->SrcIP != TRANSFER_IP_ADDRESS) {
			return 0;
		}

		__int64 key = pIPV4Hdr->DstIP;
		key = key << 16;
		key += pTcpHdr->DstPort;
		
		unordered_map<__int64, TRANSFER_ADDRESS>::iterator it = g_map.find(key);
		if (it != g_map.end()) {
			
			TRANSFER_ADDRESS *ta = &(it->second);

			char packet[0x1000];
			if (ta->tag == 0) {
				MACHEADER* mac = (MACHEADER*)packet;
				memcpy(mac->DstMAC, ta->mac.SrcMAC, MAC_ADDRESS_SIZE);
				memcpy(mac->SrcMAC, ta->mac.DstMAC, MAC_ADDRESS_SIZE);
				mac->Protocol = ta->mac.Protocol;

				memcpy(packet + sizeof(MACHEADER), pData + 4, realPackSize - 4);

				IPHEADER* ip = (IPHEADER*)(packet + ((char*)pIPV4Hdr - (char*)pData));
				TCPHEADER* tcp = (TCPHEADER*)(packet + ((char*)pTcpHdr - (char*)pData));

				ip->SrcIP = ta->ip;
				ip->HeaderChksum = 0;
				ip->HeaderChksum = Checksum::checksum((unsigned short*)ip, iIpv4HdrLen);

				iRet = pcap_sendpacket(g_pcaptLB, (const unsigned char*)packet, realPackSize + 10);
			}
			else {
				pIPV4Hdr->SrcIP = ta->ip;
				pIPV4Hdr->HeaderChksum = 0;
				pIPV4Hdr->HeaderChksum = Checksum::checksum((unsigned short*)pIPV4Hdr, iIpv4HdrLen);
				iRet = pcap_sendpacket(g_pcaptLB, (const unsigned char*)pData, realPackSize );
			}
			
			if (iRet == 0)
			{
				//Public::recorduser(pIPHdr->DstIP, dnsname);								
				//printf("process dns:%s,length:%u ok\r\n", dnsname, realPackSize + sizeof(DNSANSWER));
			}
			else {
				printf("pcap_sendpacket length:%u error\r\n", realPackSize);
			}

		}
	}
	return realPackSize;

	
}








