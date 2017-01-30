#pragma once

#include "FFGameDef.h"

#define CALL_COMPLETE   0xCF3F1F7F

#pragma pack(push, 1)
typedef struct _inject_buffer_t
{
	PLDR_LOADDLL pLdrLoadDll;
	PWCHAR pPathToFile;
	PULONG pFlags;
	PUNICODE_STRING pModuleFileName;
	PHANDLE pModuleHandle;

	UNICODE_STRING ModuleFileName;
	WCHAR FullDllPath[512];
	HANDLE ModuleHandle;
	BOOLEAN Complete;
} INJECT_BUFFER, *PINJECT_BUFFER;
#pragma pack(pop)

VOID KernelApcInjectCallback(
	IN PKAPC pKApc,
	IN PKNORMAL_ROUTINE* ppNormalRoutine,
	IN PVOID* ppNormalContext,
	IN PVOID* ppSystemArgument1,
	IN PVOID* ppSystemArgument2
);

VOID UserApcInject(
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

NTSTATUS FFAllocate(IN HANDLE pProcess, OUT PVOID *pBaseAddress, OUT PSIZE_T );

NTSTATUS FFFindModuleBase(
	IN PEPROCESS pProcess,
	IN PUNICODE_STRING pModuleName,
	OUT PVOID* pModuleBase
);