#pragma once
#include"PE.h"


/*
*	Info ��������
*		   ͨ������������Լ���shellcode
*
*	Time : 2022-1-21
*   Author : starvioder
*/

//��������ڵ�λ��
//����ֵ���������������ʵ��ͷ�ӽڱ�Ĵ�С
//		  ������������0
DWORD getNewSectionPlace(LPVOID pFileBuffer);

//Ϊ��������������
LPVOID NewSectionHeader(char Name[8], DWORD VirtualAddress, DWORD SizeOfRawData, DWORD PointerToRawData, DWORD Characteristics);

//������
LPVOID addNewSectionHeader(LPVOID pFileBuffer);