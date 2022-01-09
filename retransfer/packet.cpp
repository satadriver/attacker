

#include "Packet.h"
#include "Public.h"
#include "HttpUtils.h"
#include "checksum.h"
#include "winpcap.h"

#define MIN_PACKET_DATA_SIZE 60
#define MIN_DNS_PACKET_SIZE 20
#define CAPRAW_ERROR_FILENAME "capraw_error.txt"

#define DNS_PACKET_LIMIT 512
#define LOCAL_QUERY_DNS_ID 0xfedc
#define LOCAL_DNS_QUERY_SERVER 0x08080808


DNSANSWER		stDnsAnswer = { 0 };
unsigned long serverIP = 0;
unsigned long localIP = 0;
vector<string> dnsTargets ;
pcap_t * sendpcapT = 0;



int Packet::init(unsigned long serverip,unsigned long localip,string userPluginPath, vector<string> dnstargets,int mode,pcap_t * pcapt) {

	int iRet = 0;

	sendpcapT = pcapt;

	serverIP = serverip;
	localIP = localip;

	stDnsAnswer.Name = htons(0xc00c);
	stDnsAnswer.Type = htons(0x0001);
	stDnsAnswer.Class = htons(0x0001);
	stDnsAnswer.HighTTL = htons(0x0000);
	stDnsAnswer.LowTTL = htons(0x4040);
	stDnsAnswer.AddrLen = htons(0x0004);
	stDnsAnswer.Address = serverIP;



	dnsTargets = dnstargets;


#ifdef CLIENT_INFO_SERVICE
	iRet = Informer::init(serverIP);
	Sleep(1000);
	if (mode == 3 || mode == 4)
	{
		iRet = Informer::notify(localIP);
		//iRet = Informer::notifyInetIP(localIP);
	}
	else if (mode == 1)
	{
		iRet = Informer::notify(localIP);
	}
#endif

	return 0;
}



int Packet::parsePacket(const char * pData, int iCapLen) {
	LPPPPOEHEADER pppoe = 0;
	LPIPHEADER pIPHdr = 0;
	LPIPV6HEADER pIPV6 = 0;
	int iRet = 0;

	LPMACHEADER pMac = (LPMACHEADER)pData;

	int iptype = Packet::getIPHdr(pMac, pppoe, pIPHdr, pIPV6);
	if (iptype <= 0)
	{
		//printf("can not found ip header\r\n");
		//Public::WriteLogFile(CAPRAW_ERROR_FILENAME, (char*)pData, iCapLen);
		return -1;
	}
	else if (iptype == 1)
	{
		if (pIPHdr->Version != 4)
		{
			printf("ipv4 header version error\r\n");
			return -1;
		}

		int iIpHdrLen = pIPHdr->HeaderSize << 2;
		int iIpPackLen = ntohs(pIPHdr->PacketSize);
		int realPackSize = iIpPackLen + ((char*)pIPHdr - pData);
		
		if (realPackSize >= WINPCAP_MAX_PACKET_SIZE || realPackSize < 0)
		{
			printf("packet length:%u or ip packet length:%u or ip header length:%u error\r\n",realPackSize,iIpPackLen,iIpHdrLen);
			return -1;
		}else if (realPackSize < 60 && realPackSize >= 42)
		{
			//去掉无实际内容得tcp udp
			return realPackSize;
			//tcp connection control packet or small udp size is below 60,but caplen is at least 60
		}

		if (pIPHdr->Protocol == IPPROTO_TCP)
		{
			LPTCPHEADER pTcpHdr = (LPTCPHEADER)((char*)pIPHdr + iIpHdrLen);

			int iTcpHdrLen = pTcpHdr->HeaderSize << 2;
			char * packData = (char*)pTcpHdr + iTcpHdrLen;
			int packDataLen = iIpPackLen - (packData - (char*)pIPHdr);
			if (packDataLen <= MIN_DNS_PACKET_SIZE) {

				return realPackSize;
			}

		}
		else if (pIPHdr->Protocol == IPPROTO_UDP)
		{
			LPUDPHEADER pUdpHdr = (LPUDPHEADER)((char*)pIPHdr + iIpHdrLen);

			unsigned short usDport = ntohs(pUdpHdr->DstPort);
			if (usDport != DNS_PORT) {
				return realPackSize;
			}

			unsigned short usUdpSize = ntohs(pUdpHdr->PacketSize);

			int iDnsPackLen = usUdpSize - sizeof(UDPHEADER);
			if (iDnsPackLen >= DNS_PACKET_LIMIT || iDnsPackLen <= MIN_DNS_PACKET_SIZE)
			{
				return realPackSize;
			}

			LPDNSHEADER pDnsHdr = (LPDNSHEADER)((char*)pUdpHdr + sizeof(UDPHEADER));
			if (serverIP == localIP)
			{
				if (pDnsHdr->TransactionID == LOCAL_QUERY_DNS_ID)
				{
					if (pIPHdr->SrcIP == localIP && pIPHdr->DstIP == LOCAL_DNS_QUERY_SERVER)
					{
						return realPackSize;
					}
				}
			}

			char * iDnsQueryName = (char*)((char*)pDnsHdr + sizeof(DNSHEADER));

		}
		return realPackSize;
	}
	else if (iptype == 2)
	{
		LPIPV6HEADER pIPHdr = (LPIPV6HEADER)pIPV6;
		if (pIPHdr->Version != 6)
		{
			printf("ipv6 header version error\r\n");
			return -1;
		}

		int iIpHdrLen = sizeof(IPV6HEADER);
		int iIpPackLen = ntohs(pIPHdr->PayloadLen) ;
		int realPackSize = iIpPackLen + ((char*)pIPHdr - pData) + sizeof(IPV6HEADER);
		if (realPackSize >= WINPCAP_MAX_PACKET_SIZE || realPackSize <= 0)
		{
			printf("packet length:%u or ip packet length:%u or ip header length:%u error\r\n", realPackSize, iIpPackLen, iIpHdrLen);
			return -1;
		}

		if (pIPHdr->NextPacket == IPPROTO_TCP)
		{
			LPTCPHEADER pTcpHdr = (LPTCPHEADER)((char*)pIPHdr + iIpHdrLen);

			int iTcpHdrLen = pTcpHdr->HeaderSize << 2;
			char * packData = (char*)pTcpHdr + iTcpHdrLen;
			
			int packDataLen = ntohs(pIPHdr->PayloadLen);
			//int packDataLen = iIpPackLen - (packData - (char*)pIPHdr);
			if (packDataLen <= MIN_DNS_PACKET_SIZE) {
				return realPackSize;
			}


		}
		else if (pIPHdr->NextPacket == IPPROTO_UDP)
		{
			LPUDPHEADER pUDPHdr = (LPUDPHEADER)((char*)pIPHdr + iIpHdrLen);

			unsigned short usDport = ntohs(pUDPHdr->DstPort);
			if (usDport != DNS_PORT) {
				return realPackSize;
			}
			unsigned short usUdpSize = ntohs(pUDPHdr->PacketSize);

			unsigned int iDnsPackLen = usUdpSize - sizeof(UDPHEADER);
			if (iDnsPackLen <= MIN_DNS_PACKET_SIZE || iDnsPackLen >= DNS_PACKET_LIMIT)
			{
				return realPackSize;
			}

			LPDNSHEADER pDnsHdr = (LPDNSHEADER)((char*)pUDPHdr + sizeof(UDPHEADER));

			if (serverIP == localIP)
			{
				if (pDnsHdr->TransactionID == LOCAL_QUERY_DNS_ID)
				{
					//if (pIPHdr->SrcIP == localIP && pIPHdr->DstIP == LOCAL_DNS_SERVER)
					//{
					return realPackSize;
					//}
				}
			}

			//0x00 1c 00 01
			char * iDnsQueryName = (char*)((char*)pDnsHdr + sizeof(DNSHEADER));

		}
		return realPackSize;
	}

	return -1;
}



int Packet::getIPHdr(LPMACHEADER mac, LPPPPOEHEADER & pppoe, LPIPHEADER &ip, LPIPV6HEADER &ipv6) {
	char * nexthdr = (char*)mac + sizeof(MACHEADER);
	int nextprotocol = mac->Protocol;

	if (nextprotocol == 0x0081)
	{
		LPHEADER8021Q p8021q = (LPHEADER8021Q)nexthdr;

		if (p8021q->type == 0x0081)
		{
			LPHEADER8021Q p8021q2 = LPHEADER8021Q((char*)p8021q + sizeof(HEADER8021Q));

			nexthdr = (char*)p8021q2 + (sizeof(HEADER8021Q));

			nextprotocol = p8021q2->type;
		}
		else {
			nexthdr = (char*)p8021q + sizeof(HEADER8021Q);

			nextprotocol = p8021q->type;
		}
	}else if (nextprotocol == 0x9899 || nextprotocol == 0xa788 || nextprotocol == 0xcc88)
	{
		return 0;
	}

	//assume ip hdr is after pppoe
	//0x8863（Discovery阶段或拆链阶段）或者0x8864（Session阶段）
	if (nextprotocol == 0x6488 )
	{
		//0×C021 LCP数据报文
		//0×8021 NCP数据报文
		//0×0021 IP数据报文

		pppoe = (LPPPPOEHEADER)nexthdr;
		nextprotocol = pppoe->protocol;

		if (nextprotocol == 0x2100)
		{
			nexthdr = (char*)pppoe + sizeof(PPPOEHEADER);

			ip = (LPIPHEADER)nexthdr;

			return 1;
		}
		else if (nextprotocol == 0x5700 || nextprotocol == 0x5780) //ipv6
		{
			nexthdr = (char*)pppoe + sizeof(PPPOEHEADER);

			ipv6 = (LPIPV6HEADER)nexthdr;

			return 2;
		}
		else if (nextprotocol == 0x21c0 || nextprotocol == 0x0101 || nextprotocol == 0x23c0 || nextprotocol == 0x22c0 || nextprotocol == 0x2180)
		{
			return 0;
		}
		else {
			return -1;
		}
	}
	else if (nextprotocol == 0x0008)
	{
		ip = (LPIPHEADER)nexthdr;
		return 1;
	}
	else if (nextprotocol == 0xdd86)
	{
		ipv6 = (LPIPV6HEADER)nexthdr;

		return 2;
	}
	//0x2700 IEEE 802.3
	else if ( nextprotocol == 0x0608 || nextprotocol == 0x6388 || nextprotocol == 0x2700)
	{
		return 0;
	}
	else {
		return -1;
	}
}