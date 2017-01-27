#pragma once

#include "FFGameDef.h"

#pragma pack(push, 1)
typedef struct _copy_memory_t
{
	PVOID pLocalAddress;
	PVOID pTargetAddress;
	SIZE_T Length;
	HANDLE pTargetProcess;
	BOOLEAN   Write;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _inject_dll_t
{
	HANDLE pTargetProcess;
	PWCHAR pFullDllPath;
} INJECT_DLL, *PINJECT_DLL;
#pragma pack(pop)