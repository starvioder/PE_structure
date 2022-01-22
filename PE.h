#pragma once
#define  _CRT_SECURE_NO_WARNINGS
#include<windows.h>
#include<iostream>




/*
*	Info ：仿效PE文件加载的模式，从文件中读取到filebuffer，从filebuffer通过PE头部信息完成数据拉升
*		   得到Imagebuffer。
*		   通过Imagebuffer得到filebuffer，最后保存为文件
*
*	Time : 2022-1-19
*   Author : starvioder
*/

//将文件读取为Filebuffer
//LPCSTR lpszFile :读取文件的路径
LPVOID FileToFilebuffer(LPCSTR lpszFile);

//将Filebuffer保存为文件
//LPCSTR lpszFile :保存文件的路径
void FilebufferToFile(LPVOID pFileBuffer,LPCSTR lpszFile);

//将Filebuffer转换为Imagebuffer
LPVOID FilebufferToImagebuffer(LPVOID Filebuffer);

//将Imagebuffer转换为Filebuffer
LPVOID ImagebufferToFilebuffer(LPVOID Imagebuffer);

/*
*	Info ：计算文件或者内存合并
*		   
*
*	Time : 2022-1-22
*   Author : starvioder
*/
//计算对齐后大小 
//输入真实大小 和对齐力度  获得对齐后大小
DWORD Alignment(DWORD RealSize,DWORD AlignmentSize);

/*
*	Info ：相对虚拟地址转换为文件偏移
*
*	Time : 2022-1-22
*   Author : starvioder
*/

DWORD RvaToFov(DWORD Rva, LPVOID pFileBuffer);

/*
*	Info ：获取PE文件各个头部信息和各个节表
*
*	Time ：2022-1-17
*	Author ：starvioder
*/


//获得PE文件首地址指针
//LPVOID pFileBuffer : PE程序文件缓存
PIMAGE_DOS_HEADER getDosHeader(LPVOID pFileBuffer);

//获得PE标准文件头
//LPVOID pFileBuffer : PE程序文件缓存
PIMAGE_FILE_HEADER getFileHeader(LPVOID pFileBuffer);

//获得PE可选文件头
//LPVOID pFileBuffer : PE程序文件缓存
PIMAGE_OPTIONAL_HEADER32 getOptionHeader(LPVOID pFileBuffer);

//获得节表
//LPVOID pFileBuffer : PE程序文件缓存
PIMAGE_SECTION_HEADER getSectionHeader(LPVOID pFileBuffer);

/*
*	Info ：在命令行打印PE结构信息
*
*	Time : 2022-1-18
*   Author : starvioder
*/


//读取dos文件头 读取NT文件头  读取PE标准文件头  读取PE可选文件头  读取节表
void printNTHeader(LPCSTR FILEPATH);

//节表结构体读取
void printSection(PIMAGE_SECTION_HEADER pSectionHeader);