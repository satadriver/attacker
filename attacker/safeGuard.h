#pragma once

#include <iostream>

using namespace std;

class SafeGuard {
public:
	static int isDebuggered();

	static int __stdcall antiDebug();

	static int loginCheck(int mode,string user,string  pass);
	static int signCheck(string  tag, string user, string pass, string sign);
};