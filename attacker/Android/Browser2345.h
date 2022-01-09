
#ifndef BROWSER2345_H_H_H
#define BROWSER2345_H_H_H

#pragma once

#include "..\\ReplaceSignature.h"

class Browser2345 :public ReplaceSignature {
public:

	~Browser2345(){};

	Browser2345(unsigned long ulIP, string filepath, string filename);

};
#endif