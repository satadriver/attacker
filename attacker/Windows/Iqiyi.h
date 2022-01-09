#pragma once
#include "..\\ReplaceSignature.h"

class Iqiyi :public ReplaceSignature {
public:
	int prepareRespData(unsigned long ulIP, string filepath, string filename);

	int prepareDllRespData(unsigned ip, string filepath, string filename);

	int Iqiyi::prepareHCDNRespData(unsigned int ulIP, string filepath, string filename);
};