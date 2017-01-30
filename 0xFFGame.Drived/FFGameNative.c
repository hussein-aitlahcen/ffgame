#include "FFGameNative.h"

PVOID FFFindModuleExport(IN PVOID pBase, IN PCCHAR pOrdinalName)
{
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS pNtHdr = NULL;
	PIMAGE_EXPORT_DIRECTORY pExport = NULL;
	ULONG expSize = 0;
	ULONG_PTR pAddress = 0;

	ASSERT(pBase != NULL);
	if (pBase == NULL)
		return NULL;

	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	pNtHdr = (PIMAGE_NT_HEADERS)((PUCHAR)pBase + pDosHdr->e_lfanew);

	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
	expSize = pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	PUSHORT pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);
	PULONG  pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);
	PULONG  pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);

	for (ULONG i = 0; i < pExport->NumberOfFunctions; ++i)
	{
		PCHAR  pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)pBase);
		if (strcmp(pName, pOrdinalName) == 0)
		{
			pAddress = pAddressOfFuncs[i] + (ULONG_PTR)pBase;
			DPRINT("ffgame: %s: %s found at address 0x%X", __FUNCTION__, pName, pAddress);
			return pAddress;
		}
	}

	return NULL;
}

NTSTATUS FFFindModuleBase(IN PEPROCESS pProcess, IN PUNICODE_STRING pModuleName, OUT PVOID* pModuleBase)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PPEB pProcessPEB = NULL;
	PLIST_ENTRY pEntryCurrent = NULL, pEntryEnd = NULL;
	PLDR_DATA_TABLE_ENTRY pEntryLdr = NULL;
	LARGE_INTEGER time = 
	{ 
		.QuadPart = -250ll * 10 * 1000
	};

	pProcessPEB = PsGetProcessPeb(pProcess);
	if (!pProcessPEB)
	{
		DPRINT("ffgame: %s: PsGetProcessPeb failed\n", __FUNCTION__);
		goto cleanup;
	}

	for (SIZE_T i = 0; !pProcessPEB->Ldr && i < 10; i++)
	{
		DPRINT("ffgame: %s: Loader not intialiezd, waiting\n", __FUNCTION__);
		KeDelayExecutionThread(KernelMode, TRUE, &time);
	}

	if (!pProcessPEB->Ldr)
	{
		DPRINT("ffgame: %s: Loader was not intialiezd in time. Aborting\n", __FUNCTION__);
		Status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}

	DPRINT("ffgame: %s: finding %ls\n", __FUNCTION__, pModuleName->Buffer);

	pEntryCurrent = pEntryEnd = pProcessPEB->Ldr->InMemoryOrderModuleList.Flink;

	do
	{
		pEntryLdr = CONTAINING_RECORD(pEntryCurrent, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (RtlEqualUnicodeString(pModuleName, &pEntryLdr->BaseDllName, TRUE))
		{
			*pModuleBase = pEntryLdr->DllBase;
			DPRINT("ffgame: %s: found %ls, base address 0x%x\n", __FUNCTION__, pModuleName->Buffer, *pModuleBase);
		}
		pEntryCurrent = pEntryCurrent->Flink;
	} while (!(*pModuleBase) && pEntryCurrent != pEntryEnd);

cleanup:

	return Status;
}

NTSTATUS FFLookupProcessThread(IN HANDLE hProcess, OUT PETHREAD* ppThread)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PVOID pBuf = ExAllocatePool(NonPagedPool, 1024 * 1024);
	PSYSTEM_PROCESS_INFO pInfo = (PSYSTEM_PROCESS_INFO)pBuf;

	ASSERT(ppThread != NULL);
	if (ppThread == NULL)
		return STATUS_INVALID_PARAMETER;

	if (!pInfo)
	{
		DPRINT("ffgame: %s: Failed to allocate memory for process list\n", __FUNCTION__);
		return STATUS_NO_MEMORY;
	}

	Status = ZwQuerySystemInformation(SystemProcessInformation, pInfo, 1024 * 1024, NULL);
	if (!NT_SUCCESS(Status))
	{
		ExFreePool(pBuf);
		return Status;
	}

	if (NT_SUCCESS(Status))
	{
		Status = STATUS_NOT_FOUND;
		for (;;)
		{
			if (pInfo->UniqueProcessId == hProcess)
			{
				Status = STATUS_SUCCESS;
				break;
			}
			else if (pInfo->NextEntryOffset)
				pInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)pInfo + pInfo->NextEntryOffset);
			else
				break;
		}
	}

	if (NT_SUCCESS(Status))
	{
		Status = STATUS_NOT_FOUND;

		for (ULONG i = 0; i < pInfo->NumberOfThreads; i++)
		{
			if (pInfo->Threads[i].ClientId.UniqueThread == PsGetCurrentThread())
			{
				continue;
			}

			Status = PsLookupThreadByThreadId(pInfo->Threads[i].ClientId.UniqueThread, ppThread);
			break;
		}
	}
	else
		DPRINT("ffgame: %s: Failed to locate process\n", __FUNCTION__);

	if (pBuf)
		ExFreePool(pBuf);

	return Status;
}

VOID KernelApcPrepareCallback(
	IN PKAPC pKApc,
	IN PKNORMAL_ROUTINE* ppNormalRoutine,
	IN PVOID* ppNormalContext,
	IN PVOID* ppSystemArgument1,
	IN PVOID* ppSystemArgument2
)
{
	UNREFERENCED_PARAMETER(ppNormalRoutine);
	UNREFERENCED_PARAMETER(ppNormalContext);
	UNREFERENCED_PARAMETER(ppSystemArgument1);
	UNREFERENCED_PARAMETER(ppSystemArgument2);

	DPRINT("ffgame: %s: apc prepare\n", __FUNCTION__);

	KeTestAlertThread(UserMode);

	DPRINT("ffgame: %s: apc prepare thread alerted\n", __FUNCTION__);
	
	ExFreePool(pKApc);
}

VOID NTAPI UserApcInject(IN PVOID pContext, IN PVOID pSystemArgument1, IN PVOID pSystemArgument2)
{
	PINJECT_BUFFER pBuffer = (PINJECT_BUFFER)pContext;
	((NtLdrLoadDll)pBuffer->pLdrLoadDll)(pBuffer->pPathToFile, pBuffer->pFlags, pBuffer->pModuleFileName, pBuffer->pModuleHandle);
}

VOID KernelApcInjectCallback(
	IN PKAPC pKApc,
	IN PKNORMAL_ROUTINE* ppNormalRoutine,
	IN PVOID* ppNormalContext,
	IN PVOID* ppSystemArgument1,
	IN PVOID* ppSystemArgument2
)
{
	UNREFERENCED_PARAMETER(ppNormalContext);
	UNREFERENCED_PARAMETER(ppSystemArgument1);
	UNREFERENCED_PARAMETER(ppSystemArgument2);

	if (PsIsThreadTerminating(PsGetCurrentThread()))
	{
		*ppNormalRoutine = NULL;
	}

	DPRINT("ffgame: %s: apc inject routine=0x%X\n", __FUNCTION__, *ppNormalRoutine);

	ExFreePool(pKApc);
}

NTSTATUS FFQueueUserApc(
	IN PETHREAD pThread,
	IN PVOID pUserFunc,
	IN PVOID pArg1,
	IN PVOID pArg2,
	IN PVOID pArg3,
	IN BOOLEAN bForce)
{
	ASSERT(pThread != NULL);
	if (pThread == NULL)
		return STATUS_INVALID_PARAMETER;

	PKAPC pPrepareApc = NULL;
	PKAPC pInjectApc = ExAllocatePool(NonPagedPool, sizeof(KAPC));

	if (pInjectApc == NULL)
	{
		DPRINT("ffgame: %s: Failed to allocate APC\n", __FUNCTION__);
		return STATUS_NO_MEMORY;
	}

	KeInitializeApc(
		pInjectApc, (PKTHREAD)pThread,
		OriginalApcEnvironment, &KernelApcInjectCallback,
		NULL, (PKNORMAL_ROUTINE)(ULONG_PTR)pUserFunc, UserMode, pArg1
	);

	if (bForce)
	{
		pPrepareApc = ExAllocatePool(NonPagedPool, sizeof(KAPC));
		KeInitializeApc(
			pPrepareApc, (PKTHREAD)pThread,
			OriginalApcEnvironment, &KernelApcPrepareCallback,
			NULL, NULL, KernelMode, NULL
		);
	}

	if (KeInsertQueueApc(pInjectApc, pArg2, pArg3, IO_NO_INCREMENT))
	{
		if (bForce && pPrepareApc)
			KeInsertQueueApc(pPrepareApc, NULL, NULL, IO_NO_INCREMENT);

		return STATUS_SUCCESS;
	}
	else
	{
		DPRINT("ffgame: %s: Failed to insert APC\n", __FUNCTION__);

		ExFreePool(pInjectApc);

		if (pPrepareApc)
			ExFreePool(pPrepareApc);

		return STATUS_NOT_CAPABLE;
	}
}

NTSTATUS FFAllocate(IN HANDLE hProcess, OUT PVOID *pBaseAddress, OUT PSIZE_T Size)
{
	return ZwAllocateVirtualMemory(hProcess, pBaseAddress, 0, Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

NTSTATUS FFApcInject(IN HANDLE hProcess, IN PVOID pUserFunction, IN PVOID pUserArgument)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PETHREAD pThread = NULL;
	LARGE_INTEGER Interval =
	{
		.QuadPart = -100 * 10000
	};

	DPRINT("ffgame: %s: FFLookupProcessThread\n", __FUNCTION__);
	Status = FFLookupProcessThread(hProcess, &pThread);
	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: Failed to locate thread\n", __FUNCTION__);
		goto cleanup;
	}

	DPRINT("ffgame: %s: FFQueueUserApc\n", __FUNCTION__);
	Status = FFQueueUserApc(pThread, pUserFunction, pUserArgument, NULL, NULL, TRUE);
	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: FFQueueUserApc failed\n", __FUNCTION__);
		goto cleanup;
	}

	KeDelayExecutionThread(KernelMode, FALSE, &Interval);

	DPRINT("ffgame: %s: Apc delivered, call complete\n", __FUNCTION__);

cleanup:

	if (pThread)
		ObDereferenceObject(pThread);

	return Status;
}