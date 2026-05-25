#pragma once
#include <Windows.h>

#include <string>

#pragma comment(lib,"lib/zlib.lib")

using namespace std;

int SplitFileName(char* fn, int* filepos, int* surfix_pos);

int TestVersion(char* httphdr);

int isHttpResponse(const char* lpdata);

string getHttpHeader(const char* data, int len, char** lphttpdata);

int isHttpPacket(const char* lpdata);

string getValueFromKey(const char* lphttphdr, string  searchkey);


int getChunkSize(char* data, int* value);

int getZipType(string httphdr, char* httpdata, char* gz, int* gzsize);

int unzipWrite(HANDLE hfout, char* data, int size);