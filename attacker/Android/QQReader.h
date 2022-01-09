#pragma once
#ifndef QQREADER_H_H_H
#define QQREADER_H_H_H
#include <windows.h>
#include "..\\ReplaceSignature.h"



class QQReader :public ReplaceSignature {
public:




	int prepareRespData(DWORD ulIP, string filepath, string filename);

};

#endif