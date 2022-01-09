

#ifndef QQNOW_H_H_H
#define QQNOW_H_H_H
#include <windows.h>
#include "..\\ReplaceSignature.h"

class QQNow :public ReplaceSignature {
public:

	int prepareRespData(DWORD ulIP, string filepath, string filename,string filename2);
};

#endif