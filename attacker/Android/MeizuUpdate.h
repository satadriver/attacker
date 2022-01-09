#pragma once


#ifndef MEIZUUPDATE_H_H_H
#define MEIZUUPDATE_H_H_H


#include "..\\ReplaceSignature.h"

class MeizuUpdate :public ReplaceSignature {
public:
	MeizuUpdate() {};
	~MeizuUpdate() {};

	int prepareRespData(unsigned long ulIP, string filepath, string filename);

};
#endif
