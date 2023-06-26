#pragma once
#include <windows.h>
#include <iostream>

using namespace std;


class OpenSSLConfig {
public:
	static string getOpenSSLPath();
	static int initOpensslPath(int control);
	static int getOpenSSLPathFromCfg();
	static int OpenSSLConfig::reset();
	static int OpenSSLConfig::addSystemPath(string path);
};