#pragma once

#include <windows.h>
#include <iostream>

using namespace std;

DWORD WriteLogFile(const char * pData);
string getDateTime();
DWORD GetProcessidFromName(char * strname,int & threadcnt);
int autorun();
int killProcess(string procname);
int startProc(string procname);