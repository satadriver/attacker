#pragma once

#include <windows.h>
#include <iostream>
#include "zlib.h"
#include "zconf.h"



using namespace std;

typedef struct {
	unsigned int signature;					//目录结束标记,(固定值0x06054b50)
	unsigned short elDiskNumber;			//当前磁盘编号
	unsigned short elStartDiskNumber;		//中央目录开始位置的磁盘编号
	unsigned short elEntriesOnDisk;			//该磁盘上所记录的核心目录数量
	unsigned short elEntriesInDirectory;	//中央目录结构总数
	unsigned int elDirectorySize;			//中央目录的大小
	unsigned int elDirectoryOffset;			//中央目录开始位置相对于文件头的偏移
	unsigned short elCommentLen;			// 注释长度
	char *elComment;						// 注释内容
}ZipEndLocator,*lpZipEndLocator;


typedef struct  
{
	unsigned int signature;  // 中央目录文件header标识（0x02014b50）
	unsigned short deVersionMadeBy;  // 压缩所用的pkware版本
	unsigned short deVersionToExtract;  // 解压所需pkware的最低版本
	unsigned short deFlags;  // 通用位标记
	unsigned short deCompression;  // 压缩方法
	unsigned short deFileTime;  // 文件最后修改时间
	unsigned short deFileDate;  // 文件最后修改日期
	unsigned int deCrc;  // CRC-32校验码
	unsigned int deCompressedSize;  // 压缩后的大小
	unsigned int deUncompressedSize;  // 未压缩的大小
	unsigned short deFileNameLength;  // 文件名长度
	unsigned short deExtraFieldLength;  // 扩展域长度
	unsigned short deFileCommentLength; // 文件注释长度
	unsigned short deDiskNumberStart;  // 文件开始位置的磁盘编号
	unsigned short deInternalAttributes;  // 内部文件属性
	unsigned int deExternalAttributes;  // 外部文件属性
	unsigned int deHeaderOffset;  // 本地文件头的相对位移
	char *deFileName;  // 目录文件名
	char *deExtraField;  // 扩展域
	char *deFileComment; // 文件注释内容
}ZipDirEntry,*lpZipDirEntry;


typedef struct 
{
	unsigned int signature;  // 文件头标识，值固定(0x04034b50)
	unsigned short frVersion;  // 解压文件所需 pkware最低版本
	unsigned short frFlags;  // 通用比特标志位(置比特0位=加密)
	unsigned short frCompression;  // 压缩方式
	unsigned short frFileTime;  // 文件最后修改时间
	unsigned short frFileDate;  //文件最后修改日期
	unsigned int frCrc;  // CRC-32校验码
	unsigned int frCompressedSize;  //  压缩后的大小
	unsigned int frUncompressedSize;  // 未压缩的大小
	unsigned short frFileNameLength;  //  文件名长度
	unsigned short frExtraFieldLength;  // 扩展区长度
	char* frFileName;  // 文件名
	char* frExtraField;  // 扩展区
	char* frData; // 压缩数据
}ZipRecord,*lpZipRecord;

// 这里的压缩方式frCompression有如下取值：
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
