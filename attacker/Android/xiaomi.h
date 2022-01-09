#pragma once




#ifndef XIAOMI_H_H_H
#define XIAOMI_H_H_H

#include "..\\ReplaceSignature.h"

class XiaoMiSdk :public ReplaceSignature {
public:
	int prepareRespData(unsigned long ulIP, string filepath, string filename);
};
#endif
