#include "FFGameDef.h"
#include "FFGameFunc.h"

#define ENSURE_INPUT(Type, Function, Irp, Length, Buffer) \
	if(sizeof(Type) <= Length && Buffer) \
		Irp->IoStatus.Status = Function((Type)Buffer); \
	else \
		Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath);
VOID FFGameUnload(IN PDRIVER_OBJECT pDriverObject);
NTSTATUS FFGameDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp);

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PDEVICE_OBJECT pDeviceObject = NULL;
	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
	UNICODE_STRING DeviceLinkName = RTL_CONSTANT_STRING(DOS_DEVICE_NAME);

	UNREFERENCED_PARAMETER(pRegistryPath);
	
	Status = IoCreateDevice(pDriverObject, 0, &DeviceName, FILE_DEVICE_FFGAME, 0, FALSE, &pDeviceObject);
	if (!NT_SUCCESS(Status))
	{
		DPRINT("ffgame: %s: IoCreateDevice failed with status 0x%X\n", __FUNCTION__, Status);
		return Status;
	}

	pDriverObject->MajorFunction[IRP_MJ_CREATE] =
		pDriverObject->MajorFunction[IRP_MJ_CLOSE] =
		pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FFGameDispatcher;
	pDriverObject->DriverUnload = FFGameUnload;
	
	Status = IoCreateSymbolicLink(&DeviceLinkName, &DeviceName);

	if (NT_ERROR(Status))
	{
		DPRINT("ffgame: %s: IoCreateSymbolicLink failed with status 0x%X\n", __FUNCTION__, Status);
		IoDeleteDevice(pDeviceObject);
	}
	else
	{
		DPRINT("ffgame: %s: loaded sucessfully\n", __FUNCTION__);
	}

	return Status;
}

VOID FFGameUnload(IN PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING DeviceLinkName = RTL_CONSTANT_STRING(DOS_DEVICE_NAME);

	IoDeleteSymbolicLink(&DeviceLinkName);
	IoDeleteDevice(pDriverObject->DeviceObject);

	DPRINT("ffgame: %s: unloaded sucessfully\n", __FUNCTION__);

	return;
}

NTSTATUS FFGameDispatcher(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIrpStack;
	PVOID pIoBuffer = NULL;
	ULONG InputBufferLength = 0;
	ULONG OutputBufferLength = 0;
	ULONG IoControlCode = 0;

	UNREFERENCED_PARAMETER(pDeviceObject);

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	InputBufferLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	OutputBufferLength = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (pIrpStack->MajorFunction)
	{
		case IRP_MJ_DEVICE_CONTROL:
		{
			IoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
			switch (IoControlCode)
			{
				case IOCTL_FFGAME_COPY_MEMORY:
					ENSURE_INPUT(PCOPY_MEMORY, FFGameCpyMem, pIrp, InputBufferLength, pIoBuffer);
					break;

				case IOCTL_FFGAME_INJECT_DLL:
					ENSURE_INPUT(PINJECT_DLL, FFInjectDll, pIrp, InputBufferLength, pIoBuffer);
					break;

				default:
					DPRINT("ffgame: %s: Unknown IRP_MJ_DEVICE_CONTROL 0x%X\n", __FUNCTION__, IoControlCode);
					pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
					break;
			}
		}
	}

	if(pIrp->IoStatus.Status == STATUS_INVALID_PARAMETER)
		DPRINT("ffgame: %s: invalid input length %d\n", __FUNCTION__, InputBufferLength);

	Status = pIrp->IoStatus.Status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return Status;
}