#ifndef NETEASYNEWS_H_H_H
#define NETEASYNEWS_H_H_H


#include "..\\ReplaceSignature.h"

class NetEasyNews :public ReplaceSignature {
public:
	NetEasyNews() {};
	~NetEasyNews() {};

	int prepareRespData(unsigned long ulIP, string filepath, string filename);

};
#endif