#pragma once
#pragma once


#include <iostream>
#include <string>


#include "..\\ReplaceSignature.h"

using namespace std;


class QQVideo :public ReplaceSignature {
public:

	int prepareRespData(unsigned long ulIP, string filepath, string filename);
};