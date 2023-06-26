#pragma once
#ifndef PACKETPROC_H_H_H
#define PACKETPROC_H_H_H

#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"

#include "attack.h"
#include "attacker.h"
#include "informer.h"

#include <iostream>
#include <vector>

using namespace std;




class Packet {
public:

	Attack *attack;

	DNSANSWERIPV6	mDnsAnswerIPV6;
	DNSANSWER		mDnsAnswer;
	unsigned long	mServerIP;
	unsigned long	mLocalIP;

	pcap_t *		mPcapt;
	int				mMode;

	Packet	*		mInstance;

	Informer * mInformer;

	Packet(unsigned long serverip, unsigned long localip, string userPluginPath, int mode, pcap_t * pcapt);

	~Packet();

	int getIPHdr(LPMACHEADER mac, LPPPPOEHEADER & pppoe, LPIPHEADER &ip, LPIPV6HEADER &ipv6);

	int parsePacket(const char * pData, int iCapLen);
};


#endif