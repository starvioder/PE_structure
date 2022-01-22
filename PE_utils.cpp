#include"PE.h"

/*
*	Info ：获取PE文件各个头部信息和各个节表
*	
*	Time ：2022-1-17 
*	Author ：starvioder
*/

PIMAGE_DOS_HEADER getDosHeader(LPVOID pFileBuffer) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	if (!pFileBuffer) {
		printf("文件读取失败\n");
		
	}
	//判断是不是有效的MZ头部标志
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE) {
		printf("不是有效的MZ标志\n");
		free(pFileBuffer);
		
	}
	//获得dos头指针
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	return pDosHeader;
}

PIMAGE_FILE_HEADER getFileHeader(LPVOID pFileBuffer) {
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	//判断是否有有效的PE头
	if (*(PWORD)((DWORD)pFileBuffer + getDosHeader(pFileBuffer)->e_lfanew) != IMAGE_NT_SIGNATURE) {
		printf("不是有效的PE标志");
		free(pFileBuffer);
		
	}
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + getDosHeader(pFileBuffer)->e_lfanew + 4);
	return pPEHeader;
}

PIMAGE_OPTIONAL_HEADER32 getOptionHeader(LPVOID pFileBuffer) {
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)getFileHeader(pFileBuffer) + IMAGE_SIZEOF_FILE_HEADER);
	return pOptionHeader;
}

PIMAGE_SECTION_HEADER getSectionHeader(LPVOID pFileBuffer) {
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	pPEHeader = getFileHeader(pFileBuffer);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER + pPEHeader->SizeOfOptionalHeader);
	return pSectionHeader;
}

/*
*	Info ：仿效PE文件加载的模式，从文件中读取到filebuffer，从filebuffer通过PE头部信息完成数据拉升
*		   得到Imagebuffer。
*		   通过Imagebuffer得到filebuffer，最后保存为文件
*	
*	Time : 2022-1-19
*   Author : starvioder
*/

LPVOID FileToFilebuffer(LPCSTR lpszFile) {
	FILE* pFile = NULL;
	DWORD fileSize = 0;
	LPVOID pFileBuffer = NULL;
	//打开文件
	pFile = fopen(lpszFile, "rb");
	if (!pFile) {
		printf("无法打开.exe 文件");
		return NULL;
	}
	//读取文件大小
	//fseek函数设置文件指针的位置为文件结尾
	fseek(pFile, 0, SEEK_END);
	//ftell返回当前文件流指针的位置
	fileSize = ftell(pFile);
	//使用fseek重置文件指针位置到开头
	fseek(pFile, 0, SEEK_SET);
	//分配缓冲区
	pFileBuffer = malloc(fileSize);
	if (!pFileBuffer) {
		printf("分配空间失败！");
		fclose(pFile);
		return NULL;
	}
	//fread函数,从指定输入流中读取最多count个size大小的对象，到数组buffer
	size_t n = fread(pFileBuffer, fileSize, 1, pFile);
	if (!n) {
		printf("读取文件数据失败");
		free(pFileBuffer);
		fclose(pFile);
		return NULL;
	}
	//关闭文件
	fclose(pFile);
	return pFileBuffer;
}

LPVOID FilebufferToImagebuffer(LPVOID Filebuffer) {
	LPVOID pImageBuffer = NULL;
	LPVOID pImageOfSection = NULL;
	LPVOID pFileOfSection = NULL;
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(Filebuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = getOptionHeader(Filebuffer);
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(Filebuffer);
	DWORD ImageSize = pOptionHeader->SizeOfImage;
	DWORD ImageHeaderSize = pOptionHeader->SizeOfHeaders;
	DWORD SectionNumber = pFileHeader->NumberOfSections;

	//分配缓冲区
	pImageBuffer = malloc(ImageSize);
	if (pImageBuffer == NULL) {
		printf("内存申请失败");
		return NULL;
	}
	//初始化内存数据为0
	memset(pImageBuffer, 0, ImageSize);
	//将filebuffer中所有头和节表的数据放入Imagebuffer中
	memcpy_s(pImageBuffer, ImageHeaderSize, Filebuffer, ImageHeaderSize);
	//计算imagebuffer中第一个节表的位置
	pImageOfSection = (LPVOID)((DWORD)pImageBuffer + pSectionHeader->VirtualAddress);
	//计算filebuffer中第一个节表的位置
	pFileOfSection = (LPVOID)((DWORD)Filebuffer + pSectionHeader->PointerToRawData);
	//循环将filebuffer中各个节中的数据拷贝到imagebuffer中
	for (int i = 0; i < SectionNumber; i++) {
		memcpy_s(pImageOfSection, pSectionHeader->SizeOfRawData, pFileOfSection, pSectionHeader->SizeOfRawData);
		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);
		pImageOfSection = (LPVOID)((DWORD)pImageBuffer + pSectionHeader->VirtualAddress);
		pFileOfSection = (LPVOID)((DWORD)Filebuffer + pSectionHeader->PointerToRawData);
	}
	
	return pImageBuffer;

}

LPVOID ImagebufferToFilebuffer(LPVOID Imagebuffer) {
	LPVOID pFileBuffer = NULL;
	LPVOID pImageOfSection = NULL;
	LPVOID pFileOfSection = NULL;
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(Imagebuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = getOptionHeader(Imagebuffer);
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(Imagebuffer);
	DWORD SectionNumber = pFileHeader->NumberOfSections;

	//获得最后一个节表的指针
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + pFileHeader->NumberOfSections - 1;
	//这里有点小问题，如果在最后一个节的后面还有数据的话，会接受不到数据
	DWORD FileBufferSize = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	
	//分配缓冲区
	pFileBuffer = malloc(FileBufferSize);
	if (pFileBuffer == NULL) {
		printf("内存申请失败");
		return NULL;
	}
	//初始化
	memset(pFileBuffer, 0, FileBufferSize);
	//将所以头和节表装入FileBuffer
	memcpy_s(pFileBuffer, pOptionHeader->SizeOfHeaders, Imagebuffer, pOptionHeader->SizeOfHeaders);
	//计算filebuffer中第一个节表的位置
	pFileOfSection = (LPVOID)((DWORD)pFileBuffer + pSectionHeader->PointerToRawData);
	//计算imagebuffer中第一个节表的位置
	pImageOfSection = (LPVOID)((DWORD)Imagebuffer + pSectionHeader->VirtualAddress);
	//循环将imagebuffer中各个节中的数据拷贝到filebuffer中
	for (int i = 0; i < SectionNumber; i++) {
		memcpy_s(pFileOfSection, pSectionHeader->SizeOfRawData, pImageOfSection, pSectionHeader->SizeOfRawData);
		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);
		pImageOfSection = (LPVOID)((DWORD)Imagebuffer + pSectionHeader->VirtualAddress);
		pFileOfSection = (LPVOID)((DWORD)pFileBuffer + pSectionHeader->PointerToRawData);
	}
	return pFileBuffer;
}

void FilebufferToFile(LPVOID pFileBuffer,LPCSTR lpszFile) {
	FILE* pFile = NULL;
	size_t fileSize = _msize(pFileBuffer);
	//创建一个文件存放Filebuffer
	pFile = fopen(lpszFile, "wb");
	if (pFile == NULL) {
		printf("创建文件失败");
		return ;
	}
	//将FileBuffer中的数据写入文件中
	size_t n = fwrite(pFileBuffer,fileSize,1,pFile);
	
	free(pFileBuffer);
	pFileBuffer = NULL;
}


/*
*	Info ：计算文件或者内存合并
*
*
*	Time : 2022-1-22
*   Author : starvioder
*/

DWORD Alignment(DWORD RealSize, DWORD AlignmentSize) {
	int flag = RealSize / AlignmentSize;
	int flag_ = RealSize % AlignmentSize;
	if (flag_ == 0) {
		return AlignmentSize * flag ;
	}
	else
	{
		return AlignmentSize * (flag + 1);
	}
}

/*
*	Info ：相对虚拟地址转换为文件偏移
*
*	Time : 2022-1-22
*   Author : starvioder
*/

DWORD RvaToFov(DWORD Rva,LPVOID pFileBuffer) {
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(pFileBuffer);
	DWORD offset = 0;
	for (int i = 0; i < pFileHeader->NumberOfSections; i++) {
		if (pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData > Rva >= pSectionHeader[i].VirtualAddress) {
			offset = Rva - pSectionHeader[i].VirtualAddress;
			return pSectionHeader[i].PointerToRawData + offset;
		}
	}

}