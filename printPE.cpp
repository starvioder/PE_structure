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
	
	//���dosͷָ��
	pDosHeader = getDosHeader(pFileBuffer);
	//��ӡDOSͷ
	printf("DOSͷ��\n");
	printf("MZ��־Ϊ��%x\n", pDosHeader->e_magic);
	printf("PEͷƫ��Ϊ��%x\n", pDosHeader->e_lfanew);
	
	//���peͷָ��
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	printf("NTͷ\n");
	printf("NT��%x\n", pNTHeader->Signature);
	pPEHeader = getFileHeader(pFileBuffer);
	printf("PEͷ\n");
	printf("PE��%x\n", pPEHeader->Machine);
	printf("�ڵ�������%x\n", pPEHeader->NumberOfSections);
	printf("��ѡPEͷ��С��%x\n", pPEHeader->SizeOfOptionalHeader);
	//��ÿ�ѡPEͷָ��
	pOptionHeader = getOptionHeader(pFileBuffer);
	printf("��ѡPEͷ\n");
	printf("OPTION_PE��%x\n", pOptionHeader->Magic);
	//��ýڱ��׵�ַָ��
	pSectionHeader = getSectionHeader(pFileBuffer);
	printf("�ڱ���Ϣ\n");
	//��ýڱ�����
	SectionNumber = pPEHeader->NumberOfSections;
	printf("�ڱ�������%x\n", SectionNumber);
	//ѭ�������ڱ�����
	for (int i = 0; i < SectionNumber; i++) {
		printSection(pSectionHeader);
		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);
	}
	FilebufferToFile(pFileBuffer, "D:\\���򹤳�\\��ˮ�γ���ҵ\\��ϰ����\\IPMSG2022.exe");
	free(pFileBuffer);
}

void printSection(PIMAGE_SECTION_HEADER pSectionHeader) {
	//������  �ɸ�
	char Name[8];
	for (int i = 0; i < 8; i++) {
		Name[i] = (char)(int)pSectionHeader->Name[i];
	}
	printf("�ý����ƣ�%s\n", Name);
	printf("�ý���û�ж���ǰ����ʵ�ߴ磺%x\n", pSectionHeader->Misc.VirtualSize);
	printf("�ý����ڴ��е�ƫ�Ƶ�ַ��%x\n", pSectionHeader->VirtualAddress);
	printf("�ý����ļ��ж����ĳߴ磺%x\n", pSectionHeader->SizeOfRawData);
	printf("�ý����ļ��е�ƫ������%x\n", pSectionHeader->PointerToRawData);
	printf("�ýڵ����ԣ�%x\n", pSectionHeader->Characteristics);
}