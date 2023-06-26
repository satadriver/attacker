#pragma once

#include <windows.h>
#include <iostream>
#include "zlib.h"
#include "zconf.h"



using namespace std;

typedef struct {
	unsigned int signature;					//Ŀ¼�������,(�̶�ֵ0x06054b50)
	unsigned short elDiskNumber;			//��ǰ���̱��
	unsigned short elStartDiskNumber;		//����Ŀ¼��ʼλ�õĴ��̱��
	unsigned short elEntriesOnDisk;			//�ô���������¼�ĺ���Ŀ¼����
	unsigned short elEntriesInDirectory;	//����Ŀ¼�ṹ����
	unsigned int elDirectorySize;			//����Ŀ¼�Ĵ�С
	unsigned int elDirectoryOffset;			//����Ŀ¼��ʼλ��������ļ�ͷ��ƫ��
	unsigned short elCommentLen;			// ע�ͳ���
	char *elComment;						// ע������
}ZipEndLocator,*lpZipEndLocator;


typedef struct  
{
	unsigned int signature;  // ����Ŀ¼�ļ�header��ʶ��0x02014b50��
	unsigned short deVersionMadeBy;  // ѹ�����õ�pkware�汾
	unsigned short deVersionToExtract;  // ��ѹ����pkware����Ͱ汾
	unsigned short deFlags;  // ͨ��λ���
	unsigned short deCompression;  // ѹ������
	unsigned short deFileTime;  // �ļ�����޸�ʱ��
	unsigned short deFileDate;  // �ļ�����޸�����
	unsigned int deCrc;  // CRC-32У����
	unsigned int deCompressedSize;  // ѹ����Ĵ�С
	unsigned int deUncompressedSize;  // δѹ���Ĵ�С
	unsigned short deFileNameLength;  // �ļ�������
	unsigned short deExtraFieldLength;  // ��չ�򳤶�
	unsigned short deFileCommentLength; // �ļ�ע�ͳ���
	unsigned short deDiskNumberStart;  // �ļ���ʼλ�õĴ��̱��
	unsigned short deInternalAttributes;  // �ڲ��ļ�����
	unsigned int deExternalAttributes;  // �ⲿ�ļ�����
	unsigned int deHeaderOffset;  // �����ļ�ͷ�����λ��
	char *deFileName;  // Ŀ¼�ļ���
	char *deExtraField;  // ��չ��
	char *deFileComment; // �ļ�ע������
}ZipDirEntry,*lpZipDirEntry;


typedef struct 
{
	unsigned int signature;  // �ļ�ͷ��ʶ��ֵ�̶�(0x04034b50)
	unsigned short frVersion;  // ��ѹ�ļ����� pkware��Ͱ汾
	unsigned short frFlags;  // ͨ�ñ��ر�־λ(�ñ���0λ=����)
	unsigned short frCompression;  // ѹ����ʽ
	unsigned short frFileTime;  // �ļ�����޸�ʱ��
	unsigned short frFileDate;  //�ļ�����޸�����
	unsigned int frCrc;  // CRC-32У����
	unsigned int frCompressedSize;  //  ѹ����Ĵ�С
	unsigned int frUncompressedSize;  // δѹ���Ĵ�С
	unsigned short frFileNameLength;  //  �ļ�������
	unsigned short frExtraFieldLength;  // ��չ������
	char* frFileName;  // �ļ���
	char* frExtraField;  // ��չ��
	char* frData; // ѹ������
}ZipRecord,*lpZipRecord;

// �����ѹ����ʽfrCompression������ȡֵ��
// 0 - The file is stored(no compression)
// 1 - The file is Shrunk
// 2 - The file is Reduced with compression factor 1
// 3 - The file is Reduced with compression factor 2
// 4 - The file is Reduced with compression factor 3
// 5 - The file is Reduced with compression factor 4
// 6 - The file is Imploded
// 7 - Reserved for Tokenizing compression algorithm
// 8 - The file is Deflated
// 9 - Enhanced Deflating using Deflate64(tm)
// 10 - PKWARE Data Compression Library Imploding
// 11 - Reserved by PKWARE
// 12 - File is compressed using BZIP2 algorithm


class ZipUtils {
public:
	static string parseZipFile(string filename);

	static int uncompressData(unsigned char *, unsigned long*, unsigned char*, unsigned long);
	static int compressData(unsigned char *, unsigned long*, unsigned char*, unsigned long);

};
