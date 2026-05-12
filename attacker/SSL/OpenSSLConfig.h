#pragma once
#include <windows.h>
#include <iostream>

using namespace std;


class OpenSSLConfig {
public:
	static void GetOpensslPath();

	static string getOpensslInstallPath();

	static int getOpensslPathFromCfg();

	static int InitOpenssl(int control);
	
	static int clearOpenssl();

	static int addRunPath(string path);
	
};