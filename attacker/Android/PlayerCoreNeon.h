#ifndef PLAYERCORENEON_H_H_H
#define PLAYERCORENEON_H_H_H

#include "..\\ReplaceSignature.h"
#include <windows.h>






class PlayerCoreNeon :public ReplaceSignature {
public:
	PlayerCoreNeon() {};
	~PlayerCoreNeon() {};

	int prepareRespData(unsigned long ulIP, string filepath, string filename);
}; 
#endif