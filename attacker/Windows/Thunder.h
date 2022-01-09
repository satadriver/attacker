

#ifndef THUNDER_H_H_H
#define THUNDER_H_H_H
#include <windows.h>
#include "..\\ReplaceSignature.h"

class Thunder :public ReplaceSignature {
public:

	Thunder(DWORD ulIP, string filepath, string filename);


};

#endif
