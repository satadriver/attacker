

#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"
#include <windows.h>
#include "attacker.h"
#include "Packet.h"
#include "utils/checksum.h"
#include "ReplacePacket.h"
#include "Public.h"





int AttackPacket::ReplacePacket(pcap_t * pcapT,const char * lppacket,int packetsize,const char * lpsenddata,int sendsize,
	char * ip,int type,LPPPPOEHEADER pppoe){

	if (sendsize <= 0 || lppacket == 0 || lpsenddata == 0 )
	{
		printf("ReplacePacket packet address:%p,packet size:%u,send data:%p,send size:%u error\r\n",
			lppacket,packetsize,lpsenddata,sendsize);
		return FALSE;
	}else if (type == 2)
	{
		int ret = ReplaceIPV6Packet(pcapT, lppacket, packetsize, lpsenddata, sendsize, ip, type, pppoe);
		return ret;
	}

	LPMACHEADER lpMacHdr = (LPMACHEADER)lppacket;
	LPIPHEADER lpIPHdr = (LPIPHEADER)ip;
	int iIpHdrLen = lpIPHdr->HeaderSize << 2;
	LPTCPHEADER lpTcpHdr = (LPTCPHEADER)((char*)lpIPHdr + iIpHdrLen);
	int iTcpHdrLen = lpTcpHdr->HeaderSize << 2;
	const char * lpData = (char*)lpTcpHdr + iTcpHdrLen;
	int oldPayloadSize = packetsize - ((char*)lpData - lppacket);

	unsigned char lpnewpack[MAX_SINGLE_PACKET_SIZE];
	LPPPPOEHEADER newpppoe = 0;
	if (pppoe)
	{
		newpppoe = (LPPPPOEHEADER)((char*)pppoe - lppacket + lpnewpack);
	}
	
	int ipoffset = ip - lppacket;
	memcpy(lpnewpack, lppacket, ipoffset);
	
	LPMACHEADER lpNewMacHdr = (LPMACHEADER)lpnewpack;
	for (int i = 0; i < MAC_ADDRESS_SIZE; i++)
	{
		lpNewMacHdr->SrcMAC[i] = lpMacHdr->DstMAC[i];
		lpNewMacHdr->DstMAC[i] = lpMacHdr->SrcMAC[i];
	}
	lpNewMacHdr->Protocol = lpMacHdr->Protocol;

	LPIPHEADER lpNewIPHdr = (LPIPHEADER)(lpnewpack + ipoffset);
	memcpy((char*)lpNewIPHdr,(char*)lpIPHdr,iIpHdrLen);
	lpNewIPHdr->DstIP = lpIPHdr->SrcIP;
	lpNewIPHdr->SrcIP = lpIPHdr->DstIP;
	lpNewIPHdr->TimeToLive = 0x3f;

	LPTCPHEADER lpNewTcpHdr = (LPTCPHEADER)((char*)lpNewIPHdr + iIpHdrLen);
	memcpy(lpNewTcpHdr,lpTcpHdr,iTcpHdrLen);
	lpNewTcpHdr->SrcPort = lpTcpHdr->DstPort;
	lpNewTcpHdr->DstPort = lpTcpHdr->SrcPort;
 	lpNewTcpHdr->AckNum = ntohl(ntohl(lpTcpHdr->SeqNum) + oldPayloadSize);
 	lpNewTcpHdr->SeqNum = lpTcpHdr->AckNum;

	char * lpnewdata = (char*)lpNewTcpHdr + iTcpHdrLen;
	int senddatasize = 0;
	DWORD dwSendSeqNum = ntohl(lpNewTcpHdr->SeqNum);

	if (lpNewMacHdr->Protocol == 0x0081)
	{
		//LPHEADER8021Q lpnew8021q = (LPHEADER8021Q)((char*)lpNewMacHdr + sizeof(MACHEADER));
		//lpnew8021q->priority = 4;
	}

	int sendcnt = sendsize/MAX_PACKET_PAYLOAD;
	int sendmod = sendsize%MAX_PACKET_PAYLOAD;
	for (int i = 0; i < sendcnt; i ++)
	{
		if (pppoe)
		{
			//pppoe length include size of packetsize in pppoe
			newpppoe->len = ntohs(iIpHdrLen + iTcpHdrLen + MAX_PACKET_PAYLOAD + sizeof(WORD));
		}

		memcpy(lpnewdata,MAX_PACKET_PAYLOAD * i + lpsenddata,MAX_PACKET_PAYLOAD);
		lpNewIPHdr->PacketSize = ntohs(iIpHdrLen + iTcpHdrLen + MAX_PACKET_PAYLOAD);
		lpNewIPHdr->PacketID = ntohs(ntohs(lpNewIPHdr->PacketID)+1);
		lpNewIPHdr->HeaderChksum = 0;
		lpNewIPHdr->HeaderChksum = Checksum::checksum((WORD*)lpNewIPHdr,iIpHdrLen);

		lpNewTcpHdr->SeqNum = ntohl(dwSendSeqNum + senddatasize);
		senddatasize += MAX_PACKET_PAYLOAD;
		lpNewTcpHdr->ACK = 1;
		lpNewTcpHdr->ECN_ECHO = 0;
		lpNewTcpHdr->PacketChksum = 0;
		lpNewTcpHdr->PacketChksum = Checksum::subPackChecksum((char*)lpNewTcpHdr,
			MAX_PACKET_PAYLOAD + iTcpHdrLen,lpNewIPHdr->SrcIP,lpNewIPHdr->DstIP,IPPROTO_TCP);
		int ret = pcap_sendpacket(pcapT,lpnewpack,MAX_PACKET_PAYLOAD + ipoffset + iIpHdrLen + iTcpHdrLen);
		if (ret )
		{
			printf("ReplacePacket pcap_sendpacket error\r\n");
			Public::WriteLogFile("ReplacePacket pcap_sendpacket error\r\n");
			Public::WriteLogFile(SENDPACKET_LOG_FILENAME, lppacket, packetsize);
			return FALSE;
		}
	}

	if (sendmod)
	{
		if (pppoe)
		{
			newpppoe->len = ntohs(iIpHdrLen + iTcpHdrLen + sendmod + sizeof(WORD));
		}

		memcpy(lpnewdata,sendcnt * MAX_PACKET_PAYLOAD + lpsenddata,sendmod);
		lpNewIPHdr->PacketSize = ntohs(iIpHdrLen + iTcpHdrLen + sendmod);
		lpNewIPHdr->PacketID = ntohs(ntohs(lpNewIPHdr->PacketID)+1);
		lpNewIPHdr->HeaderChksum = 0;
		lpNewIPHdr->HeaderChksum = Checksum::checksum((WORD*)lpNewIPHdr,iIpHdrLen);

		lpNewTcpHdr->SeqNum = ntohl(dwSendSeqNum + senddatasize);
		senddatasize += sendmod;
		lpNewTcpHdr->ACK = 1;
		lpNewTcpHdr->FIN = 0;
		lpNewTcpHdr->ECN_ECHO = 0;
		lpNewTcpHdr->PacketChksum = 0;
		lpNewTcpHdr->PacketChksum = Checksum::subPackChecksum((char*)lpNewTcpHdr,sendmod+iTcpHdrLen,lpNewIPHdr->SrcIP,lpNewIPHdr->DstIP,IPPROTO_TCP);
		
		int ret = pcap_sendpacket(pcapT,lpnewpack,sendmod + ipoffset + iIpHdrLen + iTcpHdrLen);
		if (ret )
		{
			printf("ReplacePacket pcap_sendpacket error\r\n");
			Public::WriteLogFile("ReplacePacket pcap_sendpacket error\r\n");
			Public::WriteLogFile(SENDPACKET_LOG_FILENAME, lppacket, packetsize);
			return FALSE;
		}
	}


// 	int padsize = 60 - (ip - lppacket) - iIpHdrLen - iTcpHdrLen;
// 	if (padsize > 0)
// 	{
// 		memset(lpnewdata, 0, padsize);
// 	}
	
	lpNewIPHdr->PacketID = ntohs(ntohs(lpNewIPHdr->PacketID)+1);
	lpNewIPHdr->PacketSize = ntohs(iIpHdrLen + iTcpHdrLen);
	lpNewIPHdr->HeaderChksum = 0;
	lpNewIPHdr->HeaderChksum = Checksum::checksum((WORD*)lpNewIPHdr,iIpHdrLen);

	lpNewTcpHdr->FIN = 1;
	lpNewTcpHdr->ACK = 1;
	lpNewTcpHdr->SeqNum = ntohl(dwSendSeqNum + senddatasize);
	lpNewTcpHdr->PacketChksum = 0;
	lpNewTcpHdr->PacketChksum = Checksum::subPackChecksum((char*)lpNewTcpHdr,iTcpHdrLen ,lpNewIPHdr->SrcIP,lpNewIPHdr->DstIP,IPPROTO_TCP);

	int ret = pcap_sendpacket(pcapT,lpnewpack, ipoffset + iIpHdrLen + iTcpHdrLen);
	if (ret )
	{
		printf("ReplacePacket pcap_sendpacket error\r\n");
		Public::WriteLogFile("ReplacePacket pcap_sendpacket error\r\n");
		Public::WriteLogFile(SENDPACKET_LOG_FILENAME, lppacket, packetsize);
		return FALSE;
	}
	
	return TRUE;
}




int AttackPacket::ReplaceIPV6Packet(pcap_t * pcapT, const char * lppacket, int packetsize, const char * lpsenddata, int sendsize,
	char * ip, int type, LPPPPOEHEADER pppoe) {

	LPMACHEADER lpMacHdr = (LPMACHEADER)lppacket;
	LPIPV6HEADER lpIPHdr = (LPIPV6HEADER)ip;
	int iIpHdrLen = sizeof(IPV6HEADER);
	LPTCPHEADER lpTcpHdr = (LPTCPHEADER)((char*)lpIPHdr + iIpHdrLen);
	int iTcpHdrLen = lpTcpHdr->HeaderSize << 2;
	const char * lpData = (char*)lpTcpHdr + iTcpHdrLen;
	int oldPayloadSize = packetsize - ((char*)lpData - lppacket);

	unsigned char lpnewpack[MAX_SINGLE_PACKET_SIZE];
	LPPPPOEHEADER newpppoe = 0;
	if (pppoe)
	{
		newpppoe = (LPPPPOEHEADER)((char*)pppoe - lppacket + lpnewpack);
	}

	int ipoffset = ip - lppacket;
	memcpy(lpnewpack, lppacket, ipoffset);

	LPMACHEADER lpNewMacHdr = (LPMACHEADER)lpnewpack;
	for (int i = 0; i < MAC_ADDRESS_SIZE; i++)
	{
		lpNewMacHdr->SrcMAC[i] = lpMacHdr->DstMAC[i];
		lpNewMacHdr->DstMAC[i] = lpMacHdr->SrcMAC[i];
	}
	lpNewMacHdr->Protocol = lpMacHdr->Protocol;

	LPIPV6HEADER lpNewIPHdr = (LPIPV6HEADER)(lpnewpack + ipoffset);
	memcpy((char*)lpNewIPHdr, (char*)lpIPHdr, iIpHdrLen);
	memcpy(lpNewIPHdr->DestAddress ,lpIPHdr->SourceAddress,IPV6_IP_SIZE);
	memcpy(lpNewIPHdr->SourceAddress,lpIPHdr->DestAddress, IPV6_IP_SIZE);

	LPTCPHEADER lpNewTcpHdr = (LPTCPHEADER)((char*)lpNewIPHdr + iIpHdrLen);
	memcpy(lpNewTcpHdr, lpTcpHdr, iTcpHdrLen);
	lpNewTcpHdr->SrcPort = lpTcpHdr->DstPort;
	lpNewTcpHdr->DstPort = lpTcpHdr->SrcPort;
	lpNewTcpHdr->AckNum = ntohl(ntohl(lpTcpHdr->SeqNum) + oldPayloadSize);
	lpNewTcpHdr->SeqNum = lpTcpHdr->AckNum;

	char * lpnewdata = (char*)lpNewTcpHdr + iTcpHdrLen;
	int senddatasize = 0;
	DWORD dwSendSeqNum = ntohl(lpNewTcpHdr->SeqNum);

	if (lpNewMacHdr->Protocol == 0x0081)
	{
		//LPHEADER8021Q lpnew8021q = (LPHEADER8021Q)((char*)lpNewMacHdr + sizeof(MACHEADER));
		//lpnew8021q->priority = 4;
	}

	int sendcnt = sendsize / MAX_PACKET_PAYLOAD;
	int sendmod = sendsize%MAX_PACKET_PAYLOAD;
	for (int i = 0; i < sendcnt; i++)
	{
		if (pppoe)
		{
			newpppoe->len = ntohs(iIpHdrLen + iTcpHdrLen + MAX_PACKET_PAYLOAD + sizeof(WORD));
		}

		memcpy(lpnewdata, MAX_PACKET_PAYLOAD * i + lpsenddata, MAX_PACKET_PAYLOAD);
		lpNewIPHdr->PayloadLen = ntohs(iIpHdrLen + iTcpHdrLen + MAX_PACKET_PAYLOAD);

		lpNewTcpHdr->SeqNum = ntohl(dwSendSeqNum + senddatasize);
		senddatasize += MAX_PACKET_PAYLOAD;
		lpNewTcpHdr->ACK = 1;
		lpNewTcpHdr->ECN_ECHO = 0;
		lpNewTcpHdr->PacketChksum = 0;
		lpNewTcpHdr->PacketChksum = Checksum::IPV6subPackCheckSum((char*)lpNewTcpHdr,
			MAX_PACKET_PAYLOAD + iTcpHdrLen, lpNewIPHdr->SourceAddress, lpNewIPHdr->DestAddress,IPPROTO_TCP);
		int ret = pcap_sendpacket(pcapT, lpnewpack, MAX_PACKET_PAYLOAD + ipoffset + iIpHdrLen + iTcpHdrLen);
		if (ret)
		{
			printf("ReplaceIPV6Packet pcap_sendpacket error\r\n");
			return FALSE;
		}
	}

	if (sendmod)
	{
		if (pppoe)
		{
			newpppoe->len = ntohs(iIpHdrLen + iTcpHdrLen + sendmod + sizeof(WORD));
		}

		memcpy(lpnewdata, sendcnt * MAX_PACKET_PAYLOAD + lpsenddata, sendmod);
		lpNewIPHdr->PayloadLen = ntohs(iIpHdrLen + iTcpHdrLen + sendmod);

		lpNewTcpHdr->SeqNum = ntohl(dwSendSeqNum + senddatasize);
		senddatasize += sendmod;
		lpNewTcpHdr->ACK = 1;
		lpNewTcpHdr->FIN = 0;
		lpNewTcpHdr->ECN_ECHO = 0;
		//lpNewTcpHdr->SeqNum = ntohl(ntohl(lpNewTcpHdr->SeqNum) + sendmod);
		lpNewTcpHdr->PacketChksum = 0;
		lpNewTcpHdr->PacketChksum = Checksum::IPV6subPackCheckSum((char*)lpNewTcpHdr, sendmod + iTcpHdrLen,
			lpNewIPHdr->SourceAddress, lpNewIPHdr->DestAddress, IPPROTO_TCP);

		int ret = pcap_sendpacket(pcapT, lpnewpack, sendmod + ipoffset + iIpHdrLen + iTcpHdrLen);
		if (ret)
		{
			printf("ReplaceIPV6Packet pcap_sendpacket error\r\n");
			return FALSE;
		}
	}

	/*
	int padsize = 60 - (ip - lppacket) - iIpHdrLen - iTcpHdrLen;
	if (padsize > 0)
	{
		memset(lpnewdata, 0, padsize);
	}

	lpNewIPHdr->PacketID = ntohs(ntohs(lpNewIPHdr->PacketID)+1);
	lpNewIPHdr->PacketSize = ntohs(iIpHdrLen + iTcpHdrLen);
	lpNewIPHdr->HeaderChksum = 0;
	lpNewIPHdr->HeaderChksum = CalcChecksum((WORD*)lpNewIPHdr,iIpHdrLen);

	lpNewTcpHdr->FIN = 0;
	lpNewTcpHdr->SeqNum = ntohl(dwSendSeqNum + senddatasize);
	lpNewTcpHdr->PacketChksum = 0;
	lpNewTcpHdr->PacketChksum = GetSubPacketCheckSum((char*)lpNewTcpHdr,iTcpHdrLen ,lpNewIPHdr->SrcIP,lpNewIPHdr->DstIP,IPPROTO_TCP);

	int ret = pcap_sendpacket(pcapT,lpnewpack,sizeof(MACHEADER) + iIpHdrLen + iTcpHdrLen);
	if (ret )
	{
		return FALSE;
	}*/
	

	return TRUE;
}