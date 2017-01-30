// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

#define CALL_COMPLETE   0xCF3F1F7F

typedef LONG(*LdrLoadDll)(PWSTR, PULONG, PVOID, PVOID*);

#pragma pack(push, 1)
typedef struct _inject_buffer_t
{
	LdrLoadDll pLdrLoadDll;
	PWCHAR pPathToFile;
	PULONG pFlags;
	PVOID pModuleFileName;
	PHANDLE pModuleHandle;

	PVOID ModuleFileName;
	WCHAR FullDllPath[512];
	HANDLE ModuleHandle;
	BOOLEAN Complete;
} INJECT_BUFFER, *PINJECT_BUFFER;
#pragma pack(pop)


DWORD WINAPI Proc(PVOID lpThreadParameter)
{
	PINJECT_BUFFER pBuffer = (PINJECT_BUFFER)lpThreadParameter;
	((LdrLoadDll)pBuffer->pLdrLoadDll)(pBuffer->pPathToFile, pBuffer->pFlags, pBuffer->pModuleFileName, pBuffer->pModuleHandle);
	return TRUE;
}

VOID NTAPI TestInject(IN LPVOID pContext, IN LPVOID pSystemArgument1, IN LPVOID pSystemArgument2)
{
	DWORD ThreadId;
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Proc, pContext, 0, &ThreadId);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		MessageBox(NULL, L"FF the game please", L"0xFF", 0);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

