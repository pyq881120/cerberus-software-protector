#include "Misc.h"
#include "PeDiy.h"
#include <Tlhelp32.h>
//#include <Imagehlp.h>

// 链接静态库
//#pragma comment(lib, "Imagehlp.lib")

__bool __API__ Map2File(__tchar *pFilePath, __memory pMem, __integer iMemSize) {
	HANDLE hFileHandle;
	__dword dwNumWritten = 0;
	__memory aFilePtr = pMem;
	__integer aFileSize = iMemSize;

	hFileHandle = CreateFile((LPCTSTR)pFilePath, FILE_ALL_ACCESS, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (hFileHandle == INVALID_HANDLE_VALUE) {
		__dword dwErr = GetLastError();
		if ((ERROR_ALREADY_EXISTS == dwErr) || (32 == dwErr))
			return TRUE;
		return FALSE;
	}

	// 写入
	WriteFile(hFileHandle, aFilePtr, aFileSize, &dwNumWritten, NULL);
	//while (aFileSize--)
	//{
	//	WriteFile(hFileHandle, aFilePtr, 1, &dwNumWritten, NULL);
	//	aFilePtr++;
	//}
	CloseHandle(hFileHandle);
	return TRUE;
}

__bool __API__ AnsiToUnicode(__char *pSource, __word sLen, __wchar *pDestination, __word wLen) {
	return MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, pSource, sLen, pDestination, wLen);
}

__bool __API__ UnicodeToAnsi(__wchar *pSource, __word wLen, __char *pDestination, __word sLen) {
	return WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, pSource, wLen, pDestination, sLen, 0L, 0L);
}

__integer __API__ GetPidFromProcName(__tchar *lpszProcName) {
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return 0;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32)) {
		CloseHandle( hProcessSnap );
		return 0;
	}

	do {
		if (__logic_tcscpy__(pe32.szExeFile, lpszProcName) == 0) {
			CloseHandle(hProcessSnap);
			return pe32.th32ProcessID;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return 0;
}

__bool __API__ ExistFile(__tchar *lpszFilePath) {
	__dword dwFileSize = 0, dwHighSize = 0;
	HANDLE hFile = CreateFile(lpszFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, 
							  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;
	
	dwFileSize = GetFileSize(hFile, &dwHighSize);
	if (dwFileSize == 0) {
		CloseHandle(hFile);
		return FALSE;
	}

	CloseHandle(hFile);
	return TRUE;
}

//typedef enum _PROCESSINFOCLASS 
//{
//	ProcessExecuteFlags = 0x22
//} PROCESSINFOCLASS;
#define __ProcessExecuteFlags__					0x22
#define __MEM_EXECUTE_OPTION_ENABLE__			0x02
typedef __dword (__stdcall * NTSETINFORMATIONPROCESS)(HANDLE hProcessHandle, __integer ProcessInformationClass, \
													 __void *pProcessInformation, __integer iProcessInformationLength);
__bool __API__ CloseNX() {
	__dword dwExecuteFlags = __MEM_EXECUTE_OPTION_ENABLE__;
	__dword dwRet = 0;
	NTSETINFORMATIONPROCESS NtSetInformationProcess = NULL;
	HMODULE hNtdll = GetModuleHandle(_T("ntdll.dll"));
	if (hNtdll == NULL)
		return FALSE;

	NtSetInformationProcess = (NTSETINFORMATIONPROCESS)GetProcAddress(hNtdll, "NtSetInformationProcess");
	if (NtSetInformationProcess == NULL)
		return FALSE;

	// 这里调用关闭DEP
	dwRet = NtSetInformationProcess((HANDLE)GetCurrentProcess(), __ProcessExecuteFlags__, &dwExecuteFlags, sizeof(dwExecuteFlags));
	if (dwRet != 0)
		return FALSE;

	return TRUE;
}

WINDOWS_VERSION __API__ GetWindowsVersion() {
	PPEB pPeb = __NtCurrentPeb__();
	__dword dwMajorVersion = pPeb->OSMajorVersion;
	__dword dwMinorVersion = pPeb->OSMinorVersion;
	__word wBuildNumber = pPeb->OSBuildNumber;
	if (dwMajorVersion >= 6)
		return WIN_VISTA;
	else
		return WIN_XP;

	return WIN_NONE;
}

__INLINE__ __word __INTERNAL_FUNC__ LogicCalcCheckSum(__dword dwStartValue, __void *pBaseAddress, __dword dwWordCount) {
	__word *pPtr = NULL;
	__dword dwSum;
	__dword i;

	dwSum = dwStartValue;
	pPtr = (__word *)pBaseAddress;
	for (i = 0; i < dwWordCount; i++) {
		dwSum += *pPtr;
		if (HIWORD(dwSum) != 0)
			dwSum = LOWORD(dwSum) + HIWORD(dwSum);
		pPtr++;
	}

	return (__word)(LOWORD(dwSum) + HIWORD(dwSum));
}

PIMAGE_NT_HEADERS __API__ LogicCheckSumMappedFile(__void *pBaseAddress, __integer iFileLength, __dword *pdwHeaderSum, __dword *pdwCheckSum) {
	PIMAGE_NT_HEADERS pHeader;
	__dword dwCalcSum;
	__dword dwHdrSum;
	__integer iCheckSumBufferSize = (iFileLength % sizeof(__word) == 0) ? iFileLength : iFileLength + 1;
	__memory pCheckSumBuffer = (__memory)__logic_new_size__(iCheckSumBufferSize);
	__logic_memcpy__(pCheckSumBuffer, pBaseAddress, iFileLength);
	dwCalcSum = (__dword)LogicCalcCheckSum(0, pCheckSumBuffer, iCheckSumBufferSize / sizeof(__word));
	pHeader = GetNtHeader(pCheckSumBuffer);
	dwHdrSum = pHeader->OptionalHeader.CheckSum;

	/* Subtract image checksum from calculated checksum. */
	/* fix low word of checksum */
	if (LOWORD(dwCalcSum) >= LOWORD(dwHdrSum))
		dwCalcSum -= LOWORD(dwHdrSum);
	else
		dwCalcSum = ((LOWORD(dwCalcSum) - LOWORD(dwHdrSum)) & 0xFFFF) - 1;

	/* fix high word of checksum */
	if (LOWORD(dwCalcSum) >= HIWORD(dwHdrSum))
		dwCalcSum -= HIWORD(dwHdrSum);
	else
		dwCalcSum = ((LOWORD(dwCalcSum) - HIWORD(dwHdrSum)) & 0xFFFF) - 1;

	/* add file length */
	dwCalcSum += iFileLength;

	*pdwCheckSum = dwCalcSum;
	*pdwHeaderSum = pHeader->OptionalHeader.CheckSum;

	__logic_delete__(pCheckSumBuffer);
	return pHeader;
}

__dword __API__ RefixCheckSum(__memory pMem, __dword dwNewSize) {
	PIMAGE_NT_HEADERS pNtHdr = GetNtHeader(pMem);
	__dword dwCheckSum;
	if (dwNewSize == 0)
		dwCheckSum = 0;
	else {
		__dword dwHeaderSum;
		LogicCheckSumMappedFile(pMem, dwNewSize, &dwHeaderSum, &dwCheckSum);
	}
	pNtHdr->OptionalHeader.CheckSum = dwCheckSum;
	return dwCheckSum;
}

// 返回末尾自动带有"\"字符
__tchar * __API__ GetLocalPath(HMODULE hMod, __tchar *szPath) {
	__try
	{
		__tchar *p = NULL;
		//__dword dwSize = GetModuleFileName(hMod, szPath, sizeof(__tchar) * MAX_PATH);
		// MSDN的例子后面不用乘 sizeof(__tchar)
		__dword dwSize = GetModuleFileName(hMod, szPath, MAX_PATH);

		if (dwSize == 0)
			return NULL;
		p = (__tchar *)(__logic_tcsrchr__(szPath, _T('\\')) + 1);
		*p = _T('\0');//设置末尾为0
	}
	__except(__EXCEPTION_EXECUTE_HANDLER__)
	{
		return NULL;
	}

	return szPath;
}