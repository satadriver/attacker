#pragma once


#include <iostream>
#include <string>
#include "../ReplaceSignature.h"

using namespace std;


class MiguMusic:ReplaceSignature{
public:
	int MiguMusic::nextReply();
	int prepareRespData(unsigned long ulIP, string filepath, string filename);
};