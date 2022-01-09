#pragma once


#ifndef JINGDONG_H_H_H
#define JINGDONG_H_H_H
#include "..\\ReplaceSignature.h"


class JingDongPatch :public ReplaceSignature {
public:
	JingDongPatch(unsigned long ulIP, string filepath, string filename);

	int isJDNextPacket(const char * pdata, int len);
};

#endif