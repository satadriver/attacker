#pragma once
#ifndef POTATO_H_H_H
#define POTATO_H_H_H

#include "..\\ReplaceSignature.h"
#include <windows.h>





class Potato :public ReplaceSignature {
public:

	int prepareRespData(unsigned long ulIP, string filepath, string filename);
};
#endif