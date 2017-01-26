#include "FFGameFunc.h"

NTSTATUS FFGameCpyMem(IN PCOPY_MEMORY pCopy)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL, pSourceProc = NULL, pTargetProc = NULL;
	PVOID pSource = NULL, pTarget = NULL;

	DPRINT("ffgame: %s: pid=%d, targetPtr=0x%08x -> localPtr=0x%X\n", __FUNCTION__, pCopy->TargetProcess, pCopy->LocalPtr, pCopy->TargetPtr);

	Status = PsLookupProcessByProcessId(pCopy->TargetProcess, &pProcess);
	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: could not find target process\n", __FUNCTION__);
		goto exit;
	}

	SIZE_T bytes = 0;
	if (pCopy->Write != FALSE)
	{
		pSourceProc = PsGetCurrentProcess();
		pTargetProc = pProcess;
		pSource = pCopy->LocalPtr;
		pTarget = pCopy->TargetPtr;
	}
	else
	{
		pSourceProc = pProcess;
		pTargetProc = PsGetCurrentProcess();
		pSource = pCopy->TargetPtr;
		pTarget = pCopy->LocalPtr;
	}

	Status = MmCopyVirtualMemory(pSourceProc, pSource, pTargetProc, pTarget, pCopy->PtrSize, KernelMode, &bytes);

exit:
	if (pProcess)
		ObDereferenceObject(pProcess);

	return Status;
}

NTSTATUS FFInjectDll(IN PINJECT_DLL pInject)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;

	DPRINT("ffgame: %s: injecting %ls into processId %d\n", __FUNCTION__, pInject->FullDllPath, pInject->TargetProcess);

	Status = PsLookupProcessByProcessId(pInject->TargetProcess, &pProcess);
	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: could not find target process\n", __FUNCTION__);
		goto exit;
	}
		
exit:
	if (pProcess)
		ObDereferenceObject(pProcess);

	return Status;
}
