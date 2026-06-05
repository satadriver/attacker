#pragma once

#include <iostream>

using namespace std;

void LoginCheck(int mode, string username, string password, string sign);

class SafeGuard {
public:
	static int isDebuggered();

	static int __stdcall antiDebug();

	static int userCheck(int mode,string& user,string& pass);
	static int signCheck(string  tag, string user, string pass, string sign,int falg);
};