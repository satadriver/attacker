#pragma once

#include <string>
#include "SSL/sslPublic.h"

using namespace std;

class PreparePacket {
public:

	PreparePacket();
	~PreparePacket();

	PreparePacket * mInstance;

	string prepareWPS(string filename,string url);

	string PreparePacket::prepareThunder(string ver);

	string PreparePacket::prepareIqiyi(LPHTTPPROXYPARAM lphttp);
};