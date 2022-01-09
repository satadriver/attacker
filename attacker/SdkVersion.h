

#ifndef SDKVERSION_H_H_H
#define SDKVERSION_H_H_H

#define MAX_VERSION_SIZE 8

class SdkVersion {
public:
	static int GetSdkVersion(char * szsdkver, char * szversions[8]);
};


#endif