#include "FileUtils.h"
#include <windows.h>


string gParcelNames[] = {
	"webruntime.zip"
};



vector<string> getFullPaths(vector<string> fninzip,string path) {
	vector<string> fullfn;
	if (path.back() != '/' && path.back() != '\\')
	{
		path = path + "/";
	}

	for (int i = 0;i < fninzip.size();i++)
	{
		fullfn.push_back(path + fninzip[i]);
	}

	return fullfn;
}


vector<string> FileUtils::findAllFiles(string path) {

	if (path.back() != '/' && path.back() != '\\')
	{
		path = path + "/";
	}

	WIN32_FIND_DATAA finds = { 0 };

	vector<string> names;

	string findnames = path + "\\*.*";
	HANDLE h = FindFirstFileA(findnames.c_str(), &finds);
	if (h == INVALID_HANDLE_VALUE)
	{
		return names;
	}

	do 
	{
		if (lstrcmpiA(finds.cFileName,"..") == 0 || lstrcmpiA(finds.cFileName,".") == 0)
		{
			
		}
		else if (finds.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			vector<string> nextnames = findAllFiles(path + finds.cFileName + "\\");
			for (int i = 0;i < nextnames.size();i ++)
			{
				string fninzip = string(finds.cFileName) + "\\" + nextnames[i];
				names.push_back(fninzip);
			}
		}else if (finds.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE)
		{
			names.push_back(finds.cFileName);
		}
		else {
			break;
		}

		int ret = FindNextFileA(h, &finds);
		if (ret <= 0)
		{
			break;
		}
	} while (TRUE);

	CloseHandle(h);

	return names;
}