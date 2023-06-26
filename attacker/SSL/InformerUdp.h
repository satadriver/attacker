#pragma once

#include "informerClient.h"


class InformerUDP {
public:
	InformerUDP(InformerClient * client);
	~InformerUDP();

	InformerUDP * mUdp;
	InformerClient *mClients;

	static int __stdcall InformerUDP::informerUdpListener(InformerUDP * instance);

};