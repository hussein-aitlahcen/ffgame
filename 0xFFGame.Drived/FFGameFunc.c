#include "FFGameFunc.h"

NTSTATUS FFGameCpyMem(IN PCOPY_MEMORY pCopy)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL, pSourceProc = NULL, pTargetProc = NULL;
	PVOID pSource = NULL, pTarget = NULL;

	DPRINT("ffgame: %s: pid=%d, targetPtr=0x%08x -> localPtr=0x%X\n", __FUNCTION__, pCopy->pTargetProcess, pCopy->pLocalAddress, pCopy->pTargetAddress);

	Status = PsLookupProcessByProcessId(pCopy->pTargetProcess, &pProcess);
	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: could not find target process\n", __FUNCTION__);
		goto cleanup;
	}

	SIZE_T bytes = 0;
	if (pCopy->Write)
	{
		pSourceProc = PsGetCurrentProcess();
		pTargetProc = pProcess;
		pSource = pCopy->pLocalAddress;
		pTarget = pCopy->pTargetAddress;
	}
	else
	{
		pSourceProc = pProcess;
		pTargetProc = PsGetCurrentProcess();
		pSource = pCopy->pTargetAddress;
		pTarget = pCopy->pLocalAddress;
	}

	Status = MmCopyVirtualMemory(pSourceProc, pSource, pTargetProc, pTarget, pCopy->Length, KernelMode, &bytes);

cleanup:
	if (pProcess)
		ObDereferenceObject(pProcess);

	return Status;
}

NTSTATUS FFInjectDll(IN PINJECT_DLL pInject)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	HANDLE hProcess = NULL;
	PLIST_ENTRY pHeadEntry = NULL;
	PLIST_ENTRY pCurrentEntry = NULL;
	PLDR_DATA_TABLE_ENTRY pLdrEntry = NULL;
	ULONG InfoLength = 0;
	PROCESS_BASIC_INFORMATION BasicInfo;

	PAGED_CODE();

	DPRINT("ffgame: %s: injecting %ls into processId %d\n", __FUNCTION__, pInject->pFullDllPath, pInject->pTargetProcess);

	Status = PsLookupProcessByProcessId(pInject->pTargetProcess, &pProcess);
	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: PsLookupProcessByProcessId failed\n", __FUNCTION__);
		goto cleanup;
	}
	
	Status = ObOpenObjectByPointer(pProcess, OBJ_KERNEL_HANDLE, NULL, 0, NULL, KernelMode, &hProcess);
	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: ObOpenObjectByPointer failed\n", __FUNCTION__);
		goto cleanup;
	}
	
	Status = ZwQueryInformationProcess(hProcess, ProcessBasicInformation, &BasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &InfoLength);
	if (NT_ERROR(Status) || InfoLength != sizeof(PROCESS_BASIC_INFORMATION))
	{
		DPRINT("ffgame: %s: ZwQueryInformationProcess failed\n", __FUNCTION__);
		goto cleanup;
	}

	pHeadEntry = &BasicInfo.PebBaseAddress->Ldr->InMemoryOrderModuleList;
	pCurrentEntry = pHeadEntry->Flink;
	while (pCurrentEntry != pHeadEntry) 
	{
		pLdrEntry = CONTAINING_RECORD(pCurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		DPRINT("ffgame: %s: found module %ls\n", __FUNCTION__, pLdrEntry->FullDllName.Buffer);
	}

cleanup:
	if(pProcess)
		ObDereferenceObject(pProcess);

	if (hProcess)
		ZwClose(hProcess);

	return Status;
}
