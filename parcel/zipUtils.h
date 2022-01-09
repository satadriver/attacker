#pragma once

#include <windows.h>
#include <string>
#include <vector>

using namespace std;

class ZipUtils {
public:

	static int ZipUtils::zipFile(string inzipfn, string srcfn, string zipfn);


	static int ZipUtils::zipFiles(vector<string> inzipfns, vector<string> srcfns, string zipfn);

	static int ZipUtils::unzipFile(string dstpath, string zipfn);
};