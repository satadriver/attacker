

#ifndef HELPER_H_H_H
#define HELPER_H_H_H

#include <string>
#include <vector>

#define MAX_VERSION_SIZE 8

using namespace std;

#pragma pack(1)


struct UpdateData {

	string url;
	string host;
	string response;

};

#pragma pack()

extern vector < UpdateData> gUpdateData;

int ObjectParser();


class Helper {
public:
	static int GetSdkVersion(char * szsdkver, char * szversions[8]);
};


#endif