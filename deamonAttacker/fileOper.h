#pragma once


#include <windows.h>
#include <string>


using namespace std;

class FileOper {
public:
	static int FileOper::fileReader(string filename, char ** lpbuf, int *bufsize);
	static int FileOper::fileWriter(string filename, const char * lpdate, int datesize);
	static int FileOper::fileWriter(string filename, const char * lpdate, int datesize, int clear);
};


