

#ifndef CHECKSUMPACKET_H_H_H
#define CHECKSUMPACKET_H_H_H
#include "Packet.h"


class Checksum {
public:
	static WORD checksum(WORD *buffer, int size);
	static USHORT subPackChecksum(char * lpCheckSumData, WORD wCheckSumSize, DWORD dwSrcIP, DWORD dwDstIP, unsigned int wProtocol);

	static unsigned short IPV6subPackCheckSum(char * lpdata,int size,unsigned char pSrcIP[16], unsigned char pDstIP[16], unsigned short protocol);
};


#endif