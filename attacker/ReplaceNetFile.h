

#ifndef BASEFILE_H_H_H
#define BASEFILE_H_H_H


#include "ReplaceNetFile.h"
#include "ReplacePacket.h"
#include <windows.h>
#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"

#include "attacker.h"
#include "openssl/md5.h"
#include <iostream>
#include "Packet.h"


using namespace std;

#define MD5BUFFER_SIZE MD5_DIGEST_LENGTH*4

class ReplaceNetFile {
protected:
	char * m_lpdata;
	int m_datasize;
	int m_filesize;
	char m_szmd5[MD5BUFFER_SIZE];
	char mFileName[MAX_PATH];
	ReplaceNetFile *mInstance;
	
public:
	ReplaceNetFile();
	ReplaceNetFile(string filename);
	ReplaceNetFile::ReplaceNetFile(string filename, string type);

	ReplaceNetFile::ReplaceNetFile(string filename, int start, int end);
	ReplaceNetFile::ReplaceNetFile(string filename, string type, int start, int end);

	~ReplaceNetFile();

	int sendReplaceFile(pcap_t * pcapT,const char * lppacket, int packetsize, char * ip,int type,LPPPPOEHEADER pppoe);

	int ReplaceNetFile::getUpdateFileMd5(string filename, int lowercase);
};

#endif