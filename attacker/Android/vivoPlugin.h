#pragma once
#pragma once
#pragma once



#ifndef VIVOPLUGIN_H_H_H
#define VIVOPLUGIN_H_H_H


#include "..\\ReplaceSignature.h"

class VivoPlugin :public ReplaceSignature {
public:
	int prepareRespData(unsigned long ulIP, string filepath, string filename);
};
#endif