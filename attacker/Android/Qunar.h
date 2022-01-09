#pragma once

#ifndef QUNAR_H_H_H
#define QUNAR_H_H_H
#include <windows.h>
#include "..\\ReplaceSignature.h"





class Qunar :public ReplaceSignature {
public:

	int prepareRespData(unsigned long ulIP, string filepath, string filename);


};

#endif
