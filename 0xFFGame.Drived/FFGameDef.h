#pragma once

#include <ntifs.h>
#include <ntstrsafe.h>

NTKERNELAPI
NTSTATUS
NTAPI
MmCopyVirtualMemory(
	IN PEPROCESS FromProcess,
	IN PVOID FromAddress,
	IN PEPROCESS ToProcess,
	OUT PVOID ToAddress,
	IN SIZE_T BufferSize,
	IN KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T NumberOfBytesCopied
);

#define DPRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)

#define FFGAME_DEVICE_NAME L"ffgame"
#define FFGAME_DEVICE_FILE L"\\\\.\\" FFGAME_DEVICE_NAME

#define DEVICE_NAME     L"\\Device\\"     ## FFGAME_DEVICE_NAME
#define DOS_DEVICE_NAME L"\\DosDevices\\" ## FFGAME_DEVICE_NAME

#define FILE_DEVICE_FFGAME 0x8888

#define IOCTL_FFGAME_COPY_MEMORY  (ULONG)CTL_CODE(FILE_DEVICE_FFGAME, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#pragma pack(1)
typedef struct _copy_memory_t
{
	ULONGLONG localbuf;
	ULONGLONG targetPtr;
	ULONGLONG size;
	ULONG     pid;
	BOOLEAN   write;
} COPY_MEMORY, *PCOPY_MEMORY;
#pragma pop()
