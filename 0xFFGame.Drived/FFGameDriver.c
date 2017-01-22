#include "FFGameDef.h"
#include "FFGameFunc.h"

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);
VOID FFGameUnload(IN PDRIVER_OBJECT DriverObject);
NTSTATUS FFGameDispatcher(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT deviceObject = NULL;
	UNICODE_STRING deviceName;
	UNICODE_STRING deviceLink;

	UNREFERENCED_PARAMETER(RegistryPath);

	RtlUnicodeStringInit(&deviceName, DEVICE_NAME);

	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_FFGAME, 0, FALSE, &deviceObject);
	if (!NT_SUCCESS(status))
	{
		DPRINT("ffgame: %s: IoCreateDevice failed with status 0x%X\n", __FUNCTION__, status);
		return status;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] =
		DriverObject->MajorFunction[IRP_MJ_CLOSE] =
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FFGameDispatcher;
	DriverObject->DriverUnload = FFGameUnload;

	RtlUnicodeStringInit(&deviceLink, DOS_DEVICE_NAME);

	status = IoCreateSymbolicLink(&deviceLink, &deviceName);

	if (!NT_SUCCESS(status))
	{
		DPRINT("ffgame: %s: IoCreateSymbolicLink failed with status 0x%X\n", __FUNCTION__, status);
		IoDeleteDevice(deviceObject);
	}

	return status;
}

VOID FFGameUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING deviceLinkUnicodeString;

	RtlUnicodeStringInit(&deviceLinkUnicodeString, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&deviceLinkUnicodeString);
	IoDeleteDevice(DriverObject->DeviceObject);

	return;
}

NTSTATUS FFGameDispatcher(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpStack;
	PVOID ioBuffer = NULL;
	ULONG inputBufferLength = 0;
	ULONG outputBufferLength = 0;
	ULONG ioControlCode = 0;

	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	irpStack = IoGetCurrentIrpStackLocation(Irp);
	ioBuffer = Irp->AssociatedIrp.SystemBuffer;
	inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (irpStack->MajorFunction)
	{
		case IRP_MJ_DEVICE_CONTROL:
		{
			ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
			switch (ioControlCode)
			{
				case IOCTL_FFGAME_COPY_MEMORY:
					if (inputBufferLength >= sizeof(COPY_MEMORY) && ioBuffer)
						Irp->IoStatus.Status = FFGameCpyMem((PCOPY_MEMORY)ioBuffer);
					else
						Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
					break;

				default:
					DPRINT("ffgame: %s: Unknown IRP_MJ_DEVICE_CONTROL 0x%X\n", __FUNCTION__, ioControlCode);
					Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
					break;
			}
		}
	}

	status = Irp->IoStatus.Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}