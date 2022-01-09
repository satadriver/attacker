#pragma once

#include <iostream>
#include "sslpublic.h"


using namespace std;

class AuthorityCert {
public:
	static int processAuthorCert(string host,string certname,LPSSLPROXYPARAM lpparam);
};