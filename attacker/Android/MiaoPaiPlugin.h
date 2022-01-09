#pragma once
#ifndef MIAOPAIPLUGIN_H_H_H
#define MIAOPAIPLUGIN_H_H_H

#include <iostream>
#include "..\\ReplaceSignature.h"

using namespace std;

class MiaoPaiPlugin :public ReplaceSignature {
public:
	MiaoPaiPlugin(unsigned long ulIP, string filepath, string filename) ;
	~MiaoPaiPlugin() ;

	int prepareRespData(unsigned long ulIP, string filepath, string filename);

};
#endif