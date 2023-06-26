#include <windows.h>
#include "FileOper.h"


int FileOper::fileReader(string filename, char ** lpbuf, int *bufsize) {
	int ret = 0;

	FILE * fp = fopen(filename.c_str(), "rb");
	if (fp <= 0)
	{
		printf("fileReader fopen file:%s error\r\n", filename.c_str());
		return FALSE;
	}

	ret = fseek(fp, 0, FILE_END);

	int filesize = ftell(fp);

	ret = fseek(fp, 0, FILE_BEGIN);

	*bufsize = filesize;

	*lpbuf = new char[filesize + 1024];

	ret = fread(*lpbuf, 1, filesize, fp);
	fclose(fp);
	if (ret <= FALSE)
	{
		delete *lpbuf;
		return FALSE;
	}

	*(*lpbuf + filesize) = 0;
	return filesize;
}



int FileOper::fileWriter(string filename, const char * lpdate, int datesize) {
	int ret = 0;

	FILE * fp = fopen(filename.c_str(), "ab+");
	if (fp <= 0)
	{
		printf("fileReader fopen file:%s error\r\n", filename.c_str());
		return FALSE;
	}

	ret = fwrite(lpdate, 1, datesize, fp);
	fclose(fp);
	if (ret == FALSE)
	{
		return FALSE;
	}

	return datesize;
}


int FileOper::fileWriter(string filename, const char * lpdate, int datesize, int clear) {
	int ret = 0;

	FILE * fp = 0;
	if (clear) {
		fp = fopen(filename.c_str(), "wb");
	}
	else {
		fp = fopen(filename.c_str(), "ab+");
	}

	if (fp <= 0)
	{
		printf("fileReader fopen file:%s error\r\n", filename.c_str());
		return FALSE;
	}

	ret = fwrite(lpdate, 1, datesize, fp);
	fclose(fp);
	if (ret == FALSE)
	{
		return FALSE;
	}

	return datesize;
}