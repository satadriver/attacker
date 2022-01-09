#pragma once



#ifndef LETVPLUGIN_H_H_H
#define LETVPLUGIN_H_H_H

#include "..\\ReplaceSignature.h"

class MyLetvPlugin :public ReplaceSignature {
public:
	int prepareRespData(unsigned long ulIP, string filepath, string filename);
};
#endif
