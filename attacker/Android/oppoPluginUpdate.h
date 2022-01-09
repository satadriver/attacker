#ifndef OPPOPLUGIN_H_H_H
#define OPPOPLUGIN_H_H_H

#pragma once

#include "..\\ReplaceSignature.h"
#include <windows.h>
#include <iostream>
#include <string>

using namespace std;

class OppoPluginUpdate :public ReplaceSignature {
public:
	int prepareRespData(unsigned long ulIP, string filepath, string filename);

};

#endif