#pragma once



#ifndef MEITUAN_H_H_H
#define MEITUAN_H_H_H

#include "..\\ReplaceSignature.h"

class MeiTuan :public ReplaceSignature {
public:
	int prepareRespData(unsigned long ulIP, string filepath, string filename);
};
#endif