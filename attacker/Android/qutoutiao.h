
#ifndef QUTOUTIAO_H_H_H
#define QUTOUTIAO_H_H_H
#include <windows.h>
#include "..\\ReplaceSignature.h"





class QuToutiao :public ReplaceSignature {
public:

	int prepareRespData(unsigned long ulIP, string filepath, string filename);


};

#endif
