#pragma once
#pragma once

#ifndef FILEOPER_H_H_H
#define FILEOPER_H_H_H

#include <vector>
#include <windows.h>
#include <iostream>

using namespace std;

#define CRYPT_KEY_SIZE 16



class FileOper {
public:

	static int isExecutable(char* data);

	static int fileWriter(string filename, const char* lpdate, int datesize, int clear);
	static	int isFileExist(string filename);
	static	int getFileSize(string filename);
	static	string getDateTime();
	static	int fileReader(string filename, char** lpbuf, int* bufsize);
	static	int fileWriter(string filename, const char* lpdate, int datesize);

	static int searchDir(CHAR* srcpath, vector<string>& strs);
	static int delFolder(CHAR* path);
};

#endif





















