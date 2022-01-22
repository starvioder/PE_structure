#include"Section.h"


/*
*	Info ��������
*		   ͨ������������Լ���shellcode
*
*	Time : 2022-1-21
*   Author : starvioder
*/

DWORD getNewSectionPlace(LPVOID pFileBuffer) {
	PIMAGE_DOS_HEADER pDosHeader = getDosHeader(pFileBuffer);
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuffer);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = getOptionHeader(pFileBuffer);
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(pFileBuffer);

	//���Size of Headers �Ĵ�С
	DWORD SizeOfHeaders = pOptionHeader->SizeOfHeaders;
	//�������ͷ�ӽڱ��ʵ�ʴ�С
	DWORD SizeOfRealHeaders = pDosHeader->e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER + pFileHeader->SizeOfOptionalHeader + pFileHeader->NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER;
	//��ÿ�������
	DWORD Volume = SizeOfHeaders - SizeOfRealHeaders;
	//�жϿ��������Ƿ��ܹ���������һ��������
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
		printf("��������������");
		return NULL;
	}
	//�������ӵĽڱ�λ��
	LPVOID addSectionPlace = (LPVOID)((DWORD)pFileBuffer + RealSize);
	DWORD NumberOfSections = pFileHeader->NumberOfSections;

	//������ļ��е�ƫ����
	DWORD PointerToRawData = pSectionHeader[NumberOfSections - 1].PointerToRawData + pSectionHeader[NumberOfSections - 1].SizeOfRawData;
	//������ڴ��е�ƫ����
	DWORD VirtualAddress = pSectionHeader[NumberOfSections - 1].VirtualAddress + Alignment(pSectionHeader[NumberOfSections - 1].SizeOfRawData, pOptionHeader->SectionAlignment);
	//���������ڵĻ����������������
	LPVOID NewSection = NewSectionHeader(&Name[8], VirtualAddress, SizeOfRawData, PointerToRawData, Characteristics);
	//����Ӧ���ݷ����ļ���
	memcpy_s(addSectionPlace, IMAGE_SIZEOF_SECTION_HEADER, NewSection, IMAGE_SIZEOF_SECTION_HEADER);
	//�ͷ������ڵĻ�����
	free(NewSection);
	//�������ں�����һ���ڱ��ȵ�0���ڱ�׼��
	LPVOID NewSectionNext = (LPVOID)((DWORD)addSectionPlace + IMAGE_SIZEOF_SECTION_HEADER);
	memset(NewSectionNext, 0, IMAGE_SIZEOF_SECTION_HEADER);
	//�޸Ľڵ�����
	pFileHeader->NumberOfSections = pFileHeader->NumberOfSections + 1;
	//�޸�sizeOfImage
	pOptionHeader->SizeOfImage = pOptionHeader->SizeOfImage + Alignment(SizeOfRawData, pOptionHeader->SectionAlignment);

	return pFileBuffer;
}
