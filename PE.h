#pragma once
#define  _CRT_SECURE_NO_WARNINGS
#include<windows.h>
#include<iostream>




/*
*	Info ����ЧPE�ļ����ص�ģʽ�����ļ��ж�ȡ��filebuffer����filebufferͨ��PEͷ����Ϣ�����������
*		   �õ�Imagebuffer��
*		   ͨ��Imagebuffer�õ�filebuffer����󱣴�Ϊ�ļ�
*
*	Time : 2022-1-19
*   Author : starvioder
*/

//���ļ���ȡΪFilebuffer
//LPCSTR lpszFile :��ȡ�ļ���·��
LPVOID FileToFilebuffer(LPCSTR lpszFile);

//��Filebuffer����Ϊ�ļ�
//LPCSTR lpszFile :�����ļ���·��
void FilebufferToFile(LPVOID pFileBuffer,LPCSTR lpszFile);

//��Filebufferת��ΪImagebuffer
LPVOID FilebufferToImagebuffer(LPVOID Filebuffer);

//��Imagebufferת��ΪFilebuffer
LPVOID ImagebufferToFilebuffer(LPVOID Imagebuffer);

/*
*	Info �������ļ������ڴ�ϲ�
*		   
*
*	Time : 2022-1-22
*   Author : starvioder
*/
//���������С 
//������ʵ��С �Ͷ�������  ��ö�����С
DWORD Alignment(DWORD RealSize,DWORD AlignmentSize);

/*
*	Info ����������ַת��Ϊ�ļ�ƫ��
*
*	Time : 2022-1-22
*   Author : starvioder
*/

DWORD RvaToFov(DWORD Rva, LPVOID pFileBuffer);

/*
*	Info ����ȡPE�ļ�����ͷ����Ϣ�͸����ڱ�
*
*	Time ��2022-1-17
*	Author ��starvioder
*/


//���PE�ļ��׵�ַָ��
//LPVOID pFileBuffer : PE�����ļ�����
PIMAGE_DOS_HEADER getDosHeader(LPVOID pFileBuffer);

//���PE��׼�ļ�ͷ
//LPVOID pFileBuffer : PE�����ļ�����
PIMAGE_FILE_HEADER getFileHeader(LPVOID pFileBuffer);

//���PE��ѡ�ļ�ͷ
//LPVOID pFileBuffer : PE�����ļ�����
PIMAGE_OPTIONAL_HEADER32 getOptionHeader(LPVOID pFileBuffer);

//��ýڱ�
//LPVOID pFileBuffer : PE�����ļ�����
PIMAGE_SECTION_HEADER getSectionHeader(LPVOID pFileBuffer);

/*
*	Info ���������д�ӡPE�ṹ��Ϣ
*
*	Time : 2022-1-18
*   Author : starvioder
*/


//��ȡdos�ļ�ͷ ��ȡNT�ļ�ͷ  ��ȡPE��׼�ļ�ͷ  ��ȡPE��ѡ�ļ�ͷ  ��ȡ�ڱ�
void printNTHeader(LPCSTR FILEPATH);

//�ڱ�ṹ���ȡ
void printSection(PIMAGE_SECTION_HEADER pSectionHeader);