#pragma once


#include "..\\ReplaceSignature.h"

class BaiduCloud :public ReplaceSignature {

public:
	string getTypeName();
	int prepareRespData(unsigned long ulIP, string filepath, string filename);
};