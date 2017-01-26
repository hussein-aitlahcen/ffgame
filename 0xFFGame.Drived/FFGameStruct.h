#pragma once

#include "FFGameDef.h"

#pragma pack(push, 1)
typedef struct _copy_memory_t
{
	PVOID LocalPtr;
	PVOID TargetPtr;
	PVOID PtrSize;
	HANDLE TargetProcess;
	BOOLEAN   Write;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _inject_dll_t
{
	HANDLE TargetProcess;
	PWCHAR FullDllPath;
} INJECT_DLL, *PINJECT_DLL;
#pragma pack(pop)