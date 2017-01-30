#include "FFGameFunc.h"

NTSTATUS FFCopyMemory(IN PCOPY_MEMORY pCopy)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL, pSourceProc = NULL, pTargetProc = NULL;
	PVOID pSource = NULL, pTarget = NULL;

	DPRINT("ffgame: %s: pid=%d, targetPtr=0x%08x -> localPtr=0x%X\n", __FUNCTION__, pCopy->hTargetProcess, pCopy->pLocalAddress, pCopy->pTargetAddress);

	Status = PsLookupProcessByProcessId(pCopy->hTargetProcess, &pProcess);
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
	DPRINT("ffgame: %s: injecting %ls into processId %d\n", __FUNCTION__, pInject->pFullDllPath, pInject->hTargetProcess);

	NTSTATUS Status = STATUS_SUCCESS;
	PVOID pModuleBase = NULL;
	PLDR_LOADDLL pLdrLoadDll = 0;
	PEPROCESS pProcess = NULL;
	UNICODE_STRING uModuleName = RTL_CONSTANT_STRING(L"ntdll.dll");
	UNICODE_STRING uInjectDllPath;
	KAPC_STATE KApcState;
	BOOL Attached = FALSE;
	PINJECT_BUFFER pInjectBuffer = NULL;
	SIZE_T AllocateSize = PAGE_SIZE;
	LARGE_INTEGER Interval =
	{
		.QuadPart = -10 * 50
	};

	RtlInitUnicodeString(&uInjectDllPath, pInject->pFullDllPath);

	Status = PsLookupProcessByProcessId(pInject->hTargetProcess, &pProcess);
	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: PsLookupProcessByProcessId failed\n", __FUNCTION__);
		goto cleanup;
	}

	if (!pProcess)
	{
		DPRINT("ffgame: %s: pProcess NULL failed\n", __FUNCTION__);
		goto cleanup;
	}

	KeStackAttachProcess(pProcess, &KApcState);
	Attached = TRUE;

	Status = FFFindModuleBase(pProcess, &uModuleName, &pModuleBase);
	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: FFFindModuleBase failed\n", __FUNCTION__);
		goto cleanup;
	}

	pLdrLoadDll = (PLDR_LOADDLL)FFFindModuleExport(pModuleBase, "LdrLoadDll");
	if (!pLdrLoadDll)
	{
		DPRINT("ffgame: %s: FFFindModuleExport failed\n", __FUNCTION__);
		goto cleanup;
	}

	try
	{
		Status = FFAllocate(ZwCurrentProcess(), &pInjectBuffer, &AllocateSize);
		if (NT_ERROR(Status))
		{
			DPRINT("ffgame: %s: FFAllocate failed 0x%X\n", __FUNCTION__, Status);
			goto cleanup;
		}

		pInjectBuffer->pLdrLoadDll = pLdrLoadDll;
		pInjectBuffer->pFlags = NULL;
		pInjectBuffer->pPathToFile = NULL;
		pInjectBuffer->pModuleHandle = &pInjectBuffer->ModuleHandle;
		pInjectBuffer->pModuleFileName = &pInjectBuffer->ModuleFileName;
	
		pInjectBuffer->ModuleFileName.Buffer = (PWCHAR)&pInjectBuffer->FullDllPath;
		pInjectBuffer->ModuleFileName.MaximumLength = uInjectDllPath.MaximumLength;
		pInjectBuffer->ModuleFileName.Length = uInjectDllPath.Length;

		memcpy((PVOID)pInjectBuffer->FullDllPath, (PVOID)uInjectDllPath.Buffer, uInjectDllPath.Length);


		//00000	48 83 ec 28		sub	 rsp, 40; 00000028H
		//; Line 28
		//00004	4c 8b 49 20		mov	 r9, QWORD PTR[rcx + 32]
		//00008	48 8b c1		mov	 rax, rcx
		//0000b	4c 8b 41 18		mov	 r8, QWORD PTR[rcx + 24]
		//0000f	48 8b 51 10		mov	 rdx, QWORD PTR[rcx + 16]
		//00013	48 8b 49 08		mov	 rcx, QWORD PTR[rcx + 8]
		//00017	ff 10			call	 QWORD PTR[rax]
		//; Line 29
		//00019	b8 01 00 00 00	mov	 eax, 1
		//; Line 30
		//0001e	48 83 c4 28		add	 rsp, 40; 00000028H
		//00022	c3				ret	 0
		UCHAR ProcCode[] = 
		{
			0
		};

	/*	00000	48 83 ec 48	 sub	 rsp, 72; 00000048H
		00004	48 8b 05 00 00
		00 00		 mov	 rax, QWORD PTR __security_cookie
		0000b	48 33 c4	 xor	 rax, rsp
		0000e	48 89 44 24 38	 mov	 QWORD PTR __$ArrayPad$[rsp], rax
		; Line 35
		00013	48 8d 44 24 30	 lea	 rax, QWORD PTR ThreadId$[rsp]
		00018	45 33 c9	 xor	 r9d, r9d
		0001b	48 89 44 24 28	 mov	 QWORD PTR[rsp + 40], rax
		00020	4c 8d 05 00 00
		00 00		 lea	 r8, OFFSET FLAT : ? Proc@@YAKPEAX@Z; Proc
		00027	33 d2		 xor	 edx, edx
		00029	c7 44 24 20 00
		00 00 00	 mov	 DWORD PTR[rsp + 32], 0
		00031	33 c9		 xor	 ecx, ecx
		00033	ff 15 00 00 00
		00		 call	 QWORD PTR __imp_CreateThread
		; Line 36
		00039	48 8b 4c 24 38	 mov	 rcx, QWORD PTR __$ArrayPad$[rsp]
		0003e	48 33 cc	 xor	 rcx, rsp
		00041	e8 00 00 00 00	 call	 __security_check_cookie
		00046	48 83 c4 48	 add	 rsp, 72; 00000048H
		0004a	c3		 ret	 0*/
		UCHAR ApcCode[] =
		{			
			// V2
			0x4C, 0x8B, 0x49, 0x20,
			0x48, 0x8B, 0xC1,
			0x4C, 0x8B, 0x41, 0x18,
			0x48, 0x8B, 0x51, 0x10,
			0x48, 0x8B, 0x49, 0x08,
			0x48, 0xFF, 0x20

		/*	V1
			0x40, 0x53, 
			0x48, 0x83, 0xEC, 0x20, 

			0x4C, 0x8B, 0x49, 0x20, 
			0x48, 0x8B, 0xD9, 
			0x4C, 0x8B, 0x41, 0x18, 
			0x48, 0x8B, 0x51, 0x10, 
			0x48, 0x8B, 0x49, 0x08,
			0xFF, 0x13,

			0xC6, 0x83, 0x40, 0x04, 0x00, 0x00, 0x7F,

			0x48, 0x83, 0xC4, 0x20,
			0x5B,
			0xC3*/
		};

		PVOID ApcCodeAddress = (PVOID)((ULONGLONG)pInjectBuffer + sizeof(INJECT_BUFFER));
		memcpy(ApcCodeAddress, &ApcCode, sizeof(ApcCode));

		DPRINT("ffgame: %s: apc param addres=0x%X\n", __FUNCTION__, pInjectBuffer);
		DPRINT("ffgame: %s: apc code addres=0x%X\n", __FUNCTION__, ApcCodeAddress);
		FFApcInject(pInject->hTargetProcess, ApcCodeAddress, (PVOID)(ULONGLONG)pInjectBuffer);

		SIZE_T i = 0;
		while (pInjectBuffer->Complete != CALL_COMPLETE && i < 400)
		{
			KeDelayExecutionThread(KernelMode, FALSE, &Interval);
			i++;
		}

		DPRINT("ffgame: %s: Call complete\n", __FUNCTION__, pInjectBuffer);
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("ffgame: %s: Exception, Code: 0x%X\n", __FUNCTION__, GetExceptionCode());
	}

cleanup:
	if(Attached)
		KeUnstackDetachProcess(&KApcState);

	if (pProcess)
		ObDereferenceObject(pProcess);

	return Status;
}