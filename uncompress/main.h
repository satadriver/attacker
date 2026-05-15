#pragma once

#include <Windows.h>
#include <string.h>
#include <string>
#include <memory.h>
#include "compression.h"
#include <conio.h>
#include <stdio.h>

#pragma comment(lib,"lib/zlib.lib")

using namespace std;

int isHttpPacket(const char* lpdata);

string getValueFromKey(const char* lphttphdr, string  searchkey);

int getChunkSize(char* data, int* value);

int getZipType(string httphdr, char* httpdata, char* gz, int* gzsize);

int isHttpResponse(const char* lpdata);;
int unzipWrite(HANDLE hfout, char* data, int size);

string getHttpHeader(const char* data, int len, char** lphttpdata);