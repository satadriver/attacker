


#include <winsock2.h>
#include <windows.h>
#include "Packet.h"
#include "checksum.h"
#define MAX_SINGLE_PACKET_SIZE 4096


WORD Checksum::checksum(WORD *buffer,int size)
{
	unsigned long cksum = 0;
	while(1<size)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if(0<size)
		cksum += *(UCHAR*)buffer;
	cksum = (cksum>>16) + (cksum&0xffff);
	cksum += (cksum>>16);
	return(unsigned short)(~cksum);
}


USHORT Checksum::subPackChecksum(char * lpCheckSumData,WORD wCheckSumSize,DWORD dwSrcIP,DWORD dwDstIP,unsigned int wProtocol)
{
	char szCheckSumBuf[MAX_SINGLE_PACKET_SIZE];
	LPCHECKSUMFAKEHEADER lpFakeHdr = (LPCHECKSUMFAKEHEADER)szCheckSumBuf;
	lpFakeHdr->dwSrcIP = dwSrcIP;
	lpFakeHdr->dwDstIP = dwDstIP;
	lpFakeHdr->Protocol = ntohs(wProtocol);
	lpFakeHdr->usLen = ntohs(wCheckSumSize);

	memcpy(szCheckSumBuf + sizeof(CHECKSUMFAKEHEADER),(char*)lpCheckSumData,wCheckSumSize);

	*(DWORD*)(szCheckSumBuf + sizeof(CHECKSUMFAKEHEADER) + wCheckSumSize) = 0;

	unsigned short nCheckSum = checksum((WORD*)szCheckSumBuf,wCheckSumSize + sizeof(CHECKSUMFAKEHEADER));
	return nCheckSum;
}






unsigned short Checksum::IPV6subPackCheckSum(char * lpdata,int size, unsigned char pSrcIP[16], unsigned char pDstIP[16],unsigned short protocol)
{
	char szCheckSumBuf[MAX_SINGLE_PACKET_SIZE];
	LPIPV6FAKEHEADER pUdpFake = (LPIPV6FAKEHEADER)szCheckSumBuf;
	memcpy(pUdpFake->SrcIP, pSrcIP, IPV6_IP_SIZE);
	memcpy(pUdpFake->DstIP, pDstIP, IPV6_IP_SIZE);

	pUdpFake->Protocol = ntohs(protocol);
	pUdpFake->PackLen = ntohs(size);

	memcpy(szCheckSumBuf + sizeof(IPV6FAKEHEADER), (char*)lpdata, size);

	unsigned short nCheckSum = checksum((WORD*)szCheckSumBuf, size + sizeof(IPV6FAKEHEADER));
	return nCheckSum;
}