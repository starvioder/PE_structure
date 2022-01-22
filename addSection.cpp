#include"Section.h"


/*
*	Info ：新增节
*		   通过新增节添加自己的shellcode
*
*	Time : 2022-1-21
*   Author : starvioder
*/

DWORD getNewSectionPlace(LPVOID pFileBuffer) {
	PIMAGE_DOS_HEADER pDosHeader = getDosHeader(pFileBuffer);
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = getOptionHeader(pFileBuffer);
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(pFileBuffer);

	//获得Size of Headers 的大小
	DWORD SizeOfHeaders = pOptionHeader->SizeOfHeaders;
	//获得所有头加节表的实际大小
	DWORD SizeOfRealHeaders = pDosHeader->e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER + pFileHeader->SizeOfOptionalHeader + pFileHeader->NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER;
	//获得可用容量
	DWORD Volume = SizeOfHeaders - SizeOfRealHeaders;
	//判断可用容量是否能够容纳至少一个新增节
	if (Volume >= IMAGE_SIZEOF_SECTION_HEADER * 2) {
		return SizeOfRealHeaders;
	}
	else {
		return 0;
	}

}

LPVOID NewSectionHeader(char Name[8], DWORD VirtualAddress, DWORD SizeOfRawData, DWORD PointerToRawData, DWORD Characteristics) {
	LPVOID NewBuffer = NULL;
	NewBuffer = malloc(IMAGE_SIZEOF_SECTION_HEADER);
	PIMAGE_SECTION_HEADER NewSectionHeader = (PIMAGE_SECTION_HEADER)NewBuffer;
	for (int i = 0; i < IMAGE_SIZEOF_SHORT_NAME; i++) {
		NewSectionHeader->Name[i] = Name[i];
	}
	NewSectionHeader->Misc.VirtualSize = SizeOfRawData;
	NewSectionHeader->VirtualAddress = VirtualAddress;
	NewSectionHeader->SizeOfRawData = SizeOfRawData;
	NewSectionHeader->PointerToRawData = PointerToRawData;
	NewSectionHeader->Characteristics = Characteristics;
	return (LPVOID)NewSectionHeader;
}

LPVOID addNewSectionHeader(LPVOID pFileBuffer, char Name[8], DWORD Characteristics, DWORD SizeOfRawData) {
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = getOptionHeader(pFileBuffer);
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	DWORD RealSize = getNewSectionPlace(pFileBuffer);
	if (RealSize == 0) {
		printf("新增节容量不足");
		return NULL;
	}
	//获得新添加的节表位置
	LPVOID addSectionPlace = (LPVOID)((DWORD)pFileBuffer + RealSize);
	DWORD NumberOfSections = pFileHeader->NumberOfSections;

	//获得在文件中的偏移量
	DWORD PointerToRawData = pSectionHeader[NumberOfSections - 1].PointerToRawData + pSectionHeader[NumberOfSections - 1].SizeOfRawData;
	//获得在内存中的偏移量
	DWORD VirtualAddress = pSectionHeader[NumberOfSections - 1].VirtualAddress + Alignment(pSectionHeader[NumberOfSections - 1].SizeOfRawData, pOptionHeader->SectionAlignment);
	//生成新增节的缓冲区并且填充数据
	LPVOID NewSection = NewSectionHeader(&Name[8], VirtualAddress, SizeOfRawData, PointerToRawData, Characteristics);
	//将对应数据放入文件中
	memcpy_s(addSectionPlace, IMAGE_SIZEOF_SECTION_HEADER, NewSection, IMAGE_SIZEOF_SECTION_HEADER);
	//释放新增节的缓冲区
	free(NewSection);
	//在新增节后增加一个节表长度的0用于标准化
	LPVOID NewSectionNext = (LPVOID)((DWORD)addSectionPlace + IMAGE_SIZEOF_SECTION_HEADER);
	memset(NewSectionNext, 0, IMAGE_SIZEOF_SECTION_HEADER);
	//修改节的数量
	pFileHeader->NumberOfSections = pFileHeader->NumberOfSections + 1;
	//修改sizeOfImage
	pOptionHeader->SizeOfImage = pOptionHeader->SizeOfImage + Alignment(SizeOfRawData, pOptionHeader->SectionAlignment);

	return pFileBuffer;
}
