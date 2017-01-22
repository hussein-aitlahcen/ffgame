#include "FFGameFunc.h"

NTSTATUS FFGameCpyMem(IN PCOPY_MEMORY pCopy)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL, pSourceProc = NULL, pTargetProc = NULL;
	PVOID pSource = NULL, pTarget = NULL;

	status = PsLookupProcessByProcessId((HANDLE)pCopy->pid, &pProcess);

	if (NT_SUCCESS(status))
	{
		SIZE_T bytes = 0;
		if (pCopy->write != FALSE)
		{
			pSourceProc = PsGetCurrentProcess();
			pTargetProc = pProcess;
			pSource = (PVOID)pCopy->localbuf;
			pTarget = (PVOID)pCopy->targetPtr;
		}
		else
		{
			pSourceProc = pProcess;
			pTargetProc = PsGetCurrentProcess();
			pSource = (PVOID)pCopy->targetPtr;
			pTarget = (PVOID)pCopy->localbuf;
		}

		status = MmCopyVirtualMemory(pSourceProc, pSource, pTargetProc, pTarget, pCopy->size, KernelMode, &bytes);
	}
	else
		DPRINT("ffgame: %s: PsLookupProcessByProcessId failed with status 0x%X\n", __FUNCTION__, status);

	if (pProcess)
		ObDereferenceObject(pProcess);

	return status;
}