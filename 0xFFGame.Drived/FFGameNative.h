#pragma once

#include "FFGameDef.h"

#define CALL_COMPLETE   0xCF3F1F7F

typedef struct _ldr_load_dll_t
{
	PWCHAR PathToFile;
	PULONG Flags;
	PUNICODE_STRING pModuleFileName;
	PHANDLE pModuleHandle;

	UNICODE_STRING ModuleFileName;
	WCHAR FullDllPath[512];
	HANDLE ModuleHandle;
} LDR_LOAD_DLL_T, *PLDR_LOAD_DLL_T;

VOID KernelApcInjectCallback(
	IN PKAPC pKApc,
	IN PKNORMAL_ROUTINE* ppNormalRoutine,
	IN PVOID* ppNormalContext,
	IN PVOID* ppSystemArgument1,
	IN PVOID* ppSystemArgument2
);

VOID NTAPI UserApcInject(
	IN PVOID pNormalContext, 
	IN PVOID pSystemArgument1, 
	IN PVOID pSystemArgument2
);

NTSTATUS FFApcInject(
	IN HANDLE hProcess, 
	IN PVOID pUserFunction, 
	IN PVOID pUserArgument
);

NTSTATUS FFQueueUserApc(
	IN PETHREAD pThread,
	IN PVOID pUserFunc,
	IN PVOID pArg1,
	IN PVOID pArg2,
	IN PVOID pArg3,
	IN BOOLEAN bForce);

NTSTATUS FFLookupProcessThread(
	IN HANDLE hProcess,
	OUT PETHREAD* ppThread
);

PVOID FFFindModuleExport(
	IN PVOID pBase, 
	IN PCCHAR pOrdinalName
);

NTSTATUS FFAllocate(OUT PVOID *pBaseAddress, OUT PSIZE_T );

NTSTATUS FFFindModuleBase(
	IN PEPROCESS pProcess,
	IN PUNICODE_STRING pModuleName,
	OUT PVOID* pModuleBase
);