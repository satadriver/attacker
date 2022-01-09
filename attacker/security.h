#pragma once

#include <iostream>

using namespace std;

class Security {
public:
	static int isDebuggered();
	static int __stdcall antiDebug();

	static int loginCheck(int runmode,string &user,string & pass);
};