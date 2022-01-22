#include"PE.h"

void printNTHeader(LPCSTR FILEPATH) {
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	int SectionNumber = 0;

	pFileBuffer = FileToFilebuffer(FILEPATH);
	
	//获得dos头指针
	pDosHeader = getDosHeader(pFileBuffer);
	//打印DOS头
	printf("DOS头部\n");
	printf("MZ标志为：%x\n", pDosHeader->e_magic);
	printf("PE头偏移为：%x\n", pDosHeader->e_lfanew);
	
	//获得pe头指针
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	printf("NT头\n");
	printf("NT：%x\n", pNTHeader->Signature);
	pPEHeader = getFileHeader(pFileBuffer);
	printf("PE头\n");
	printf("PE：%x\n", pPEHeader->Machine);
	printf("节的数量：%x\n", pPEHeader->NumberOfSections);
	printf("可选PE头大小：%x\n", pPEHeader->SizeOfOptionalHeader);
	//获得可选PE头指针
	pOptionHeader = getOptionHeader(pFileBuffer);
	printf("可选PE头\n");
	printf("OPTION_PE：%x\n", pOptionHeader->Magic);
	//获得节表首地址指针
	pSectionHeader = getSectionHeader(pFileBuffer);
	printf("节表信息\n");
	//获得节表数量
	SectionNumber = pPEHeader->NumberOfSections;
	printf("节表数量：%x\n", SectionNumber);
	//循环遍历节表内容
	for (int i = 0; i < SectionNumber; i++) {
		printSection(pSectionHeader);
		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);
	}
	FilebufferToFile(pFileBuffer, "D:\\逆向工程\\滴水课程作业\\练习材料\\IPMSG2022.exe");
	free(pFileBuffer);
}

void printSection(PIMAGE_SECTION_HEADER pSectionHeader) {
	//节名称  可改
	char Name[8];
	for (int i = 0; i < 8; i++) {
		Name[i] = (char)(int)pSectionHeader->Name[i];
	}
	printf("该节名称：%s\n", Name);
	printf("该节在没有对齐前的真实尺寸：%x\n", pSectionHeader->Misc.VirtualSize);
	printf("该节在内存中的偏移地址：%x\n", pSectionHeader->VirtualAddress);
	printf("该节在文件中对齐后的尺寸：%x\n", pSectionHeader->SizeOfRawData);
	printf("该节在文件中的偏移量：%x\n", pSectionHeader->PointerToRawData);
	printf("该节的属性：%x\n", pSectionHeader->Characteristics);
}