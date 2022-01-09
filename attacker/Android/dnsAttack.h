#pragma once

#pragma once
#ifndef DNSATTACK_H_H_H
#define DNSATTACK_H_H_H


#include "..\\ReplaceSignature.h"
#include <iostream>

using namespace std;

class DnsAttack :public ReplaceSignature {
public:
	DnsAttack(unsigned long ulIP, string filepath, string filename);
};



#endif
