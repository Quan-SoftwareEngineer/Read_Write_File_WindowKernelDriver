#include "ntddk.h"
#include "ntstrsafe.h"
#define  BUFFER_SIZE 98


VOID Unload(IN PDRIVER_OBJECT DriverObject)
{
	DbgPrint("driver unload \r\n");
}
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	DriverObject->DriverUnload = Unload;

    UNICODE_STRING     uniName;
    OBJECT_ATTRIBUTES  objAttr;

    CHAR     buffer[BUFFER_SIZE];
    RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\1.txt");  // or L"\\SystemRoot\\example.txt"
    InitializeObjectAttributes(&objAttr, &uniName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL, NULL);

    HANDLE   handle;
    NTSTATUS ntstatus;
    IO_STATUS_BLOCK    ioStatusBlock;

    // Do not try to perform any file operations at higher IRQL levels.
    // Instead, you may use a work item or a system worker thread to perform file operations.

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    ntstatus = ZwCreateFile(&handle,
        GENERIC_ALL,
        &objAttr, &ioStatusBlock, NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);


    LARGE_INTEGER      byteOffset;



    size_t  cb;

    if (NT_SUCCESS(ntstatus)) {
        ntstatus = RtlStringCbPrintfA(buffer, sizeof(buffer), "This is %d test write overwrite\r\n", 0x0);
        if (NT_SUCCESS(ntstatus)) {
            ntstatus = RtlStringCbLengthA(buffer, sizeof(buffer), &cb);
            if (NT_SUCCESS(ntstatus)) {
                ntstatus = ZwWriteFile(handle, NULL, NULL, NULL, &ioStatusBlock,
                    buffer, cb, NULL, NULL);
            }
        }
        ZwClose(handle);
    }


    ntstatus = ZwCreateFile(&handle,
        GENERIC_READ,
        &objAttr, &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    if (NT_SUCCESS(ntstatus)) {
        byteOffset.LowPart = byteOffset.HighPart = 0;
        ntstatus = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock,
            buffer, BUFFER_SIZE, &byteOffset, NULL);
        if (NT_SUCCESS(ntstatus)) {
            buffer[BUFFER_SIZE - 1] = '\0';
            DbgPrint("%s\n", buffer);
        }
        ZwClose(handle);
    }



	return STATUS_SUCCESS;
}