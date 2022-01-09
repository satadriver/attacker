#pragma once


#ifndef NETCARDINFO_H_H_H
#define NETCARDINFO_H_H_H


#include <iostream>
#include <IPTypes.h>

using namespace std;

class NetCardInfo {
public:
	static PIP_ADAPTER_INFO ShowNetCardInfo(int *);
	static PIP_ADAPTER_INFO GetNetCardAdapter(PIP_ADAPTER_INFO pAdapterInfo, int seq);

	static string NetCardInfo::selectWeapon(unsigned long * localIP, unsigned long * netmask, unsigned long * netgate, unsigned char *, string tips);
};

#endif