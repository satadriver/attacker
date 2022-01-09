

#ifndef KUGOU_H_H_H
#define KUGOU_H_H_H

#include "..\\ReplaceSignature.h"

class Kugou :public ReplaceSignature {
	public:
		int prepareRespData(unsigned long ulIP, string filepath, string filename);
};
#endif