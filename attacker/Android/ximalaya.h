#pragma once

#ifndef XIMALAYA_H_H_H
#define XIMALAYA_H_H_H


#include "..\\ReplaceSignature.h"

class Ximalaya :public ReplaceSignature {
public:


	int prepareRespData(unsigned long ulIP, string filepath, string filename);

};
#endif