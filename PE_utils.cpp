#include"PE.h"

/*
*	Info ����ȡPE�ļ�����ͷ����Ϣ�͸����ڱ�
*	
*	Time ��2022-1-17 
*	Author ��starvioder
*/

PIMAGE_DOS_HEADER getDosHeader(LPVOID pFileBuffer) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	if (!pFileBuffer) {
		printf("�ļ���ȡʧ��\n");
		
	}
	//�ж��ǲ�����Ч��MZͷ����־
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE) {
		printf("������Ч��MZ��־\n");
		free(pFileBuffer);
		
	}
	//���dosͷָ��
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	return pDosHeader;
}

PIMAGE_FILE_HEADER getFileHeader(LPVOID pFileBuffer) {
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	//�ж��Ƿ�����Ч��PEͷ
	if (*(PWORD)((DWORD)pFileBuffer + getDosHeader(pFileBuffer)->e_lfanew) != IMAGE_NT_SIGNATURE) {
		printf("������Ч��PE��־");
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
*	Info ����ЧPE�ļ����ص�ģʽ�����ļ��ж�ȡ��filebuffer����filebufferͨ��PEͷ����Ϣ�����������
*		   �õ�Imagebuffer��
*		   ͨ��Imagebuffer�õ�filebuffer����󱣴�Ϊ�ļ�
*	
*	Time : 2022-1-19
*   Author : starvioder
*/

LPVOID FileToFilebuffer(LPCSTR lpszFile) {
	FILE* pFile = NULL;
	DWORD fileSize = 0;
	LPVOID pFileBuffer = NULL;
	//���ļ�
	pFile = fopen(lpszFile, "rb");
	if (!pFile) {
		printf("�޷���.exe �ļ�");
		return NULL;
	}
	//��ȡ�ļ���С
	//fseek���������ļ�ָ���λ��Ϊ�ļ���β
	fseek(pFile, 0, SEEK_END);
	//ftell���ص�ǰ�ļ���ָ���λ��
	fileSize = ftell(pFile);
	//ʹ��fseek�����ļ�ָ��λ�õ���ͷ
	fseek(pFile, 0, SEEK_SET);
	//���仺����
	pFileBuffer = malloc(fileSize);
	if (!pFileBuffer) {
		printf("����ռ�ʧ�ܣ�");
		fclose(pFile);
		return NULL;
	}
	//fread����,��ָ���������ж�ȡ���count��size��С�Ķ��󣬵�����buffer
	size_t n = fread(pFileBuffer, fileSize, 1, pFile);
	if (!n) {
		printf("��ȡ�ļ�����ʧ��");
		free(pFileBuffer);
		fclose(pFile);
		return NULL;
	}
	//�ر��ļ�
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

	//���仺����
	pImageBuffer = malloc(ImageSize);
	if (pImageBuffer == NULL) {
		printf("�ڴ�����ʧ��");
		return NULL;
	}
	//��ʼ���ڴ�����Ϊ0
	memset(pImageBuffer, 0, ImageSize);
	//��filebuffer������ͷ�ͽڱ�����ݷ���Imagebuffer��
	memcpy_s(pImageBuffer, ImageHeaderSize, Filebuffer, ImageHeaderSize);
	//����imagebuffer�е�һ���ڱ��λ��
	pImageOfSection = (LPVOID)((DWORD)pImageBuffer + pSectionHeader->VirtualAddress);
	//����filebuffer�е�һ���ڱ��λ��
	pFileOfSection = (LPVOID)((DWORD)Filebuffer + pSectionHeader->PointerToRawData);
	//ѭ����filebuffer�и������е����ݿ�����imagebuffer��
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

	//������һ���ڱ��ָ��
	PIMAGE_SECTION_HEADER pLastSectionHeader = pSectionHeader + pFileHeader->NumberOfSections - 1;
	//�����е�С���⣬��������һ���ڵĺ��滹�����ݵĻ�������ܲ�������
	DWORD FileBufferSize = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
	
	//���仺����
	pFileBuffer = malloc(FileBufferSize);
	if (pFileBuffer == NULL) {
		printf("�ڴ�����ʧ��");
		return NULL;
	}
	//��ʼ��
	memset(pFileBuffer, 0, FileBufferSize);
	//������ͷ�ͽڱ�װ��FileBuffer
	memcpy_s(pFileBuffer, pOptionHeader->SizeOfHeaders, Imagebuffer, pOptionHeader->SizeOfHeaders);
	//����filebuffer�е�һ���ڱ��λ��
	pFileOfSection = (LPVOID)((DWORD)pFileBuffer + pSectionHeader->PointerToRawData);
	//����imagebuffer�е�һ���ڱ��λ��
	pImageOfSection = (LPVOID)((DWORD)Imagebuffer + pSectionHeader->VirtualAddress);
	//ѭ����imagebuffer�и������е����ݿ�����filebuffer��
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
	//����һ���ļ����Filebuffer
	pFile = fopen(lpszFile, "wb");
	if (pFile == NULL) {
		printf("�����ļ�ʧ��");
		return ;
	}
	//��FileBuffer�е�����д���ļ���
	size_t n = fwrite(pFileBuffer,fileSize,1,pFile);
	
	free(pFileBuffer);
	pFileBuffer = NULL;
}


/*
*	Info �������ļ������ڴ�ϲ�
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
*	Info ����������ַת��Ϊ�ļ�ƫ��
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