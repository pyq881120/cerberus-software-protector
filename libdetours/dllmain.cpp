#include "AnalyzeNetBank.h"
#include <Windows.h>

extern BOOL g_LoadIt;
BOOL APIENTRY DllMain( HMODULE hModule,
					  DWORD  ul_reason_for_call,
					  LPVOID lpReserved
					  )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
		if (g_LoadIt)
			return TRUE;
		else {
			StartAnalyze(hModule);
		}
	break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_DETACH:
		//StopFuckCmbc();
	break;
	}
	return TRUE;
}

