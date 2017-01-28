#include "FFGameFunc.h"

NTSTATUS FFCopyMemory(IN PCOPY_MEMORY pCopy)
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
	DPRINT("ffgame: %s: injecting %ls into processId %d\n", __FUNCTION__, pInject->pFullDllPath, pInject->pTargetProcess);

	PVOID pModuleBase = NULL;
	UNICODE_STRING uModuleName = RTL_CONSTANT_STRING(L"ntdll.dll");

	NTSTATUS Status = FFFindModuleBase(pInject->pTargetProcess, &uModuleName, &pModuleBase);

	return Status;
}