#pragma once
#include"PE.h"


/*
*	Info ：新增节
*		   通过新增节添加自己的shellcode
*
*	Time : 2022-1-21
*   Author : starvioder
*/

//获得新增节的位置
//返回值：如果能新增返回实际头加节表的大小
//		  不能新增返回0
DWORD getNewSectionPlace(LPVOID pFileBuffer);

//为新增节填入数据
LPVOID NewSectionHeader(char Name[8], DWORD VirtualAddress, DWORD SizeOfRawData, DWORD PointerToRawData, DWORD Characteristics);

//新增节
LPVOID addNewSectionHeader(LPVOID pFileBuffer);