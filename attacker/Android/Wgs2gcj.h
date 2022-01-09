#pragma once


#ifndef Wgs2gcj_H_H_H
#define Wgs2gcj_H_H_H
#include "..\\ReplaceSignature.h"
#include "../ReplaceNetFile.h"

class Wgs2gcj :public ReplaceNetFile {
public:
	int PrepareReplaceFile( string filename);
};

#endif