#pragma once


#ifndef DUOMIMUSIC_H_H_H
#define DUOMIMUSIC_H_H_H


#include "..\\ReplaceSignature.h"

class DuomiMusic :public ReplaceSignature {
public:
	DuomiMusic() {};
	~DuomiMusic() {};

	DuomiMusic(unsigned long ulIP, string filepath, string filename);

};
#endif

