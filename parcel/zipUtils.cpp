

#undef _UNICODE
#undef  UNICODE



#include "ZipUtils.h"

#include <windows.h>
#include <iostream>
#include <string>

#include "zip.h"
#include "zlib.h"
#include "zconf.h"



using namespace std;


int ZipUtils::zipFile(string inzipfn, string srcfn, string zipfn) {
	ZRESULT ret = 0;
	HZIP hz = CreateZip((const TCHAR*)zipfn.c_str(), (const char*)0);
	if (hz)
	{
		ret = ZipAdd(hz, inzipfn.c_str(), srcfn.c_str());
		CloseZip(hz);
		return TRUE;
	}

	return FALSE;
}


int ZipUtils::zipFiles(vector<string> inzipfns, vector<string> srcfns, string zipfn) {
	ZRESULT ret = 0;
	HZIP hz = CreateZip((TCHAR*)zipfn.c_str(), 0);
	if (hz)
	{
		for (int i = 0; i < inzipfns.size(); i++)
		{
			ret = ZipAdd(hz, inzipfns[i].c_str(), srcfns[i].c_str());
		}

		CloseZip(hz);
		return TRUE;
	}

	return FALSE;
}


int ZipUtils::unzipFile(string dstpath, string zipfn) {
// 	TCHAR zipPath[MAX_PATH] = { 0 };	
// 	TCHAR destDir[MAX_PATH] = { 0 };	
// 	string2tchar(res, zipPath);	
// 	string2tchar(sDstDir, destDir);	
// 	TCHAR zipPath[MAX_PATH] = { 0 };	TCHAR destDir[MAX_PATH] = { 0 };	string2tchar(res, zipPath);	string2tchar(sDstDir, destDir);	hz = OpenZip(zipPath, 0);	SetUnzipBaseDir(hz, destDir);	ZIPENTRY ze; GetZipItem(hz, -1, &ze); int numitems = ze.index;	for (int zi = 0; zi < numitems; zi++) { GetZipItem(hz, zi, &ze);		UnzipItem(hz, zi, ze.name); }	CloseZip(hz);
// 	HZIP hz = OpenZip(zipPath, 0);	
// 	SetUnzipBaseDir(hz, destDir);	
// 	ZIPENTRY ze; 
// 	GetZipItem(hz, -1, &ze); 
// 	int numitems = ze.index;	
// 	for (int zi = 0; zi < numitems; zi++) { 
// 		GetZipItem(hz, zi, &ze);		
// 		UnzipItem(hz, zi, ze.name); 
// 	}	
// 	CloseZip(hz);

	return 0;
}