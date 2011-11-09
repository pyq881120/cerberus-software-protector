// fuckme.cpp : 定义控制台应用程序的入口点。
//
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <Windows.h>

typedef VOID (__stdcall *FPFuckYou)();

int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE hModule = INVALID_HANDLE_VALUE;
	FPFuckYou pFuckYou = NULL;
	printf("hello world\r\n");
	hModule = LoadLibrary(_T("fuckyou.dll"));
	pFuckYou = (FPFuckYou)GetProcAddress((HMODULE)hModule, "FuckYou");
	pFuckYou();
	return 0;
}

