#pragma once
#pragma once


#include "..\\ReplaceSignature.h"

class Haozip :public ReplaceSignature {

public:
	string getTypeName();
	int prepareRespData(unsigned long ulIP, string filepath, string filename);
};