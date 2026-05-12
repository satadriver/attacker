#pragma once

#include "InformerInterface.h"


class InformerSvrUDP {
public:
	InformerSvrUDP(InformerInterface* client);
	~InformerSvrUDP();

	InformerSvrUDP* mUdp;
	InformerInterface*mClients;

	static int __stdcall informerUdpListener(InformerSvrUDP* instance);

};