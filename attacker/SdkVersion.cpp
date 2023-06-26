
#include <windows.h>

#include "SdkVersion.h"



int SdkVersion::GetSdkVersion(char* szsdkver, char* szversions[8]) {
	int j = 0;
	szversions[j] = szsdkver;
	j++;
	int sdklen = lstrlenA(szsdkver);
	for (int i = 0; i < sdklen; i++)
	{
		if (szsdkver[i] == '.')
		{
			szsdkver[i] = 0;

			szversions[j] = szsdkver + i + 1;
			j++;
		}
	}

	return j;
}




