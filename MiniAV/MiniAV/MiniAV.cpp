#include <ntifs.h>

#define AV_DEVICE_TYPE 0x8000
#define IOCTL_INIT CTL_CODE(AV_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CHECK_INIT CTL_CODE(AV_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BLACKLIST_PROCESS CTL_CODE(AV_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WHITELIST_PROCESS CTL_CODE(AV_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DUMP_PROCESS CTL_CODE(AV_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KILL_PROCESS CTL_CODE(AV_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)


#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE (0x0001)
#endif


typedef struct _DUMP_REQUEST {
    ULONG pid;
    ULONG size;
    WCHAR dumpfile[260];
} DUMP_REQUEST, * PDUMP_REQUEST;


PUNICODE_STRING blacklistProcess = NULL;
PUNICODE_STRING whitelistProcess = NULL;
ERESOURCE listLock;
KMUTEX mutex;
BOOLEAN isInitialized = FALSE;


typedef PVOID(*PSGETPROCESSSECTIONBASEADDRESS)(PEPROCESS Process);
PSGETPROCESSSECTIONBASEADDRESS PsGetProcessSectionBaseAddress = NULL;



void ToLowercase(PUNICODE_STRING str) {
    for (USHORT i = 0; i < str->Length / sizeof(WCHAR); i++) {
        str->Buffer[i] = towlower(str->Buffer[i]);
    }
}


BOOLEAN IsProcessBlacklisted(PUNICODE_STRING processName) {
    BOOLEAN result = FALSE;
    ExAcquireResourceSharedLite(&listLock, TRUE);

    if (blacklistProcess != NULL && blacklistProcess->Buffer != NULL) {
        if (RtlCompareUnicodeString(blacklistProcess, processName, TRUE) == 0) {
            result = TRUE;
        }
    }

    ExReleaseResourceLite(&listLock);
    return result;
}


BOOLEAN IsProcessWhitelisted(PUNICODE_STRING processName) {
    BOOLEAN result = FALSE;
    ExAcquireResourceSharedLite(&listLock, TRUE);

    if (whitelistProcess != NULL && whitelistProcess->Buffer != NULL) {
        if (RtlCompareUnicodeString(whitelistProcess, processName, TRUE) == 0) {
            result = TRUE;
        }
    }

    ExReleaseResourceLite(&listLock);
    return result;
}


VOID ProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);

    // Skip processing during initialization
    if (!isInitialized) {
        return;
    }

    if (CreateInfo != NULL) { // Process is being created
        UNICODE_STRING exeName;
        UNICODE_STRING fullProcessName;
        PWCHAR buffer;
        USHORT length;

        // Extract the full path of the executable
        RtlInitUnicodeString(&fullProcessName, CreateInfo->ImageFileName->Buffer);

        // Check if the buffer is not NULL before proceeding
        if (fullProcessName.Buffer != NULL) {
            buffer = fullProcessName.Buffer;
            length = fullProcessName.Length / sizeof(WCHAR);

            // Find the last occurrence of '\\' in the path
            while (length > 0 && buffer[length - 1] != L'\\') {
                length--;
            }

            if (length > 0) {
                buffer = &buffer[length];
            }

            RtlInitUnicodeString(&exeName, buffer);
            ToLowercase(&exeName); // Convert to lowercase

            // Compare the extracted name with the blacklist entries
            if (IsProcessBlacklisted(&exeName)) {
                CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                DbgPrint("Blocked process: %wZ\n", &exeName);
            }

            else if (!IsProcessWhitelisted(&exeName) && whitelistProcess->Length > 0) {
                CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                DbgPrint("Blocked non-whitelisted process: %wZ\n", &exeName);
            }
        }
    }
}


NTSTATUS DumpProcessMemory(ULONG pid, ULONG size, PWCHAR dumpfile, PIRP Irp) {
    UNREFERENCED_PARAMETER(Irp);
    PEPROCESS Process;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &Process);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Error: PsLookupProcessByProcessId failed with status 0x%X\n", status);
        return status;
    }

    KAPC_STATE apcState;
    KeStackAttachProcess(Process, &apcState);

    PVOID baseAddress = PsGetProcessSectionBaseAddress(Process);
    if (baseAddress == NULL) {
        KeUnstackDetachProcess(&apcState);
        DbgPrint("Error: PsGetProcessSectionBaseAddress returned NULL\n");
        return STATUS_UNSUCCESSFUL;
    }

    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatusBlock;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING dumpfileName;
    RtlInitUnicodeString(&dumpfileName, dumpfile);

    InitializeObjectAttributes(&objectAttributes, &dumpfileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateFile(&fileHandle, GENERIC_WRITE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status)) {
        KeUnstackDetachProcess(&apcState);
        DbgPrint("Error: ZwCreateFile failed with status 0x%X\n", status);
        return status;
    }

    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'AVDT'); // Allocate memory to copy
    if (!buffer) {
        ZwClose(fileHandle);
        KeUnstackDetachProcess(&apcState);
        DbgPrint("Error: ExAllocatePool2 failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        memcpy(buffer, baseAddress, size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("Error: Exception in memcpy with status 0x%X\n", status);
    }

    if (NT_SUCCESS(status)) {
        status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, buffer, size, NULL, NULL);
        if (!NT_SUCCESS(status)) {
            DbgPrint("Error: ZwWriteFile failed with status 0x%X\n", status);
        }
    }

    ExFreePoolWithTag(buffer, 'AVDT');
    ZwClose(fileHandle);
    KeUnstackDetachProcess(&apcState);

    return status;
}


NTSTATUS KillProcess(ULONG pid) {
    PEPROCESS Process;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &Process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    HANDLE processHandle;
    status = ObOpenObjectByPointer(Process, 0, NULL, PROCESS_TERMINATE, NULL, KernelMode, &processHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ZwTerminateProcess(processHandle, 0);
    ZwClose(processHandle);
    return status;
}


NTSTATUS DriverCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


NTSTATUS DriverIoControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_SUCCESS;

    switch (controlCode) {
    case IOCTL_INIT: {
        KeWaitForSingleObject(&mutex, Executive, KernelMode, FALSE, NULL);

        if (blacklistProcess == NULL) {
            blacklistProcess = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'TAG1');
            if (blacklistProcess == NULL) {
                DbgPrint("Failed to allocate memory for blacklistProcess structure\n");
                ExReleaseResourceLite(&listLock);
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            RtlZeroMemory(blacklistProcess, sizeof(UNICODE_STRING));
        }

        if (whitelistProcess == NULL) {
            whitelistProcess = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'TAG2');
            if (whitelistProcess == NULL) {
                DbgPrint("Failed to allocate memory for whitelistProcess structure\n");
                ExReleaseResourceLite(&listLock);
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            RtlZeroMemory(whitelistProcess, sizeof(UNICODE_STRING));
        }

        isInitialized = TRUE;
        KeReleaseMutex(&mutex, FALSE);
        DbgPrint("Initialized successfully!\n");
        break;
    }

    case IOCTL_CHECK_INIT: {
        BOOLEAN* initStatus = (BOOLEAN*)Irp->AssociatedIrp.SystemBuffer;
        *initStatus = isInitialized;
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_BLACKLIST_PROCESS: {
        ExAcquireResourceExclusiveLite(&listLock, TRUE);

        // Check and remove from whitelist if it exists
        if (whitelistProcess != NULL) {
            if (whitelistProcess->Buffer != NULL) {
                ExFreePoolWithTag(whitelistProcess->Buffer, 'TAG2');
                whitelistProcess->Buffer = NULL;
            }

            RtlZeroMemory(whitelistProcess, sizeof(UNICODE_STRING));
        }

        if (blacklistProcess->Buffer != NULL) {
            ExFreePoolWithTag(blacklistProcess->Buffer, 'TAG1');
            blacklistProcess->Buffer = NULL;
        }

        PCWSTR inputBuffer = (PCWSTR)Irp->AssociatedIrp.SystemBuffer;
        USHORT inputLength = (USHORT)(wcslen(inputBuffer) * sizeof(WCHAR));

        blacklistProcess->Buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, inputLength + sizeof(WCHAR), 'TAG1');
        if (blacklistProcess->Buffer == NULL) {
            DbgPrint("Failed to allocate memory for blacklistProcess buffer\n");
            ExReleaseResourceLite(&listLock);
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        RtlCopyMemory(blacklistProcess->Buffer, inputBuffer, inputLength);
        blacklistProcess->Buffer[inputLength / sizeof(WCHAR)] = L'\0';

        blacklistProcess->Length = inputLength;
        blacklistProcess->MaximumLength = inputLength + sizeof(WCHAR);

        ToLowercase(blacklistProcess);

        DbgPrint("Set blacklist process: %wZ\n", blacklistProcess);

        ExReleaseResourceLite(&listLock);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_WHITELIST_PROCESS: {
        ExAcquireResourceExclusiveLite(&listLock, TRUE);

        // Check and remove from blacklist if it exists
        if (blacklistProcess != NULL) {
            if (blacklistProcess->Buffer != NULL) {
                ExFreePoolWithTag(blacklistProcess->Buffer, 'TAG1');
                blacklistProcess->Buffer = NULL;
            }

            RtlZeroMemory(blacklistProcess, sizeof(UNICODE_STRING));
        }

        if (whitelistProcess->Buffer != NULL) {
            ExFreePoolWithTag(whitelistProcess->Buffer, 'TAG2');
            whitelistProcess->Buffer = NULL;
        }

        PCWSTR inputBuffer = (PCWSTR)Irp->AssociatedIrp.SystemBuffer;
        USHORT inputLength = (USHORT)(wcslen(inputBuffer) * sizeof(WCHAR));

        whitelistProcess->Buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, inputLength + sizeof(WCHAR), 'TAG2');
        if (whitelistProcess->Buffer == NULL) {
            DbgPrint("Failed to allocate memory for whitelistProcess buffer\n");
            ExReleaseResourceLite(&listLock);
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        RtlCopyMemory(whitelistProcess->Buffer, inputBuffer, inputLength);
        whitelistProcess->Buffer[inputLength / sizeof(WCHAR)] = L'\0';

        whitelistProcess->Length = inputLength;
        whitelistProcess->MaximumLength = inputLength + sizeof(WCHAR);

        ToLowercase(whitelistProcess);

        DbgPrint("Set whitelistProcess process: %wZ\n", whitelistProcess);

        ExReleaseResourceLite(&listLock);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_DUMP_PROCESS: {
        PDUMP_REQUEST dumpRequest = (PDUMP_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        if (dumpRequest == NULL) {
            DbgPrint("Error: Received NULL DUMP_REQUEST\n");
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        DbgPrint("Received DUMP_PROCESS request: pid=%lu, size=%lu, dumpfile=%ws\n", dumpRequest->pid, dumpRequest->size, dumpRequest->dumpfile);
        status = DumpProcessMemory(dumpRequest->pid, dumpRequest->size, dumpRequest->dumpfile, Irp);
        break;
    }

    case IOCTL_KILL_PROCESS: {
        ULONG pid = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
        status = KillProcess(pid);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        KdPrint(("Invalid device request.\n"));
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = (status == STATUS_SUCCESS) ? sizeof(ULONG) : 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}


void UnloadDriver(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\??\\MiniAV");

    IoDeleteSymbolicLink(&symbolicLink);
    IoDeleteDevice(DriverObject->DeviceObject);

    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);

    ExDeleteResourceLite(&listLock);

    // Free allocated memory
    if (blacklistProcess) {
        if (blacklistProcess->Buffer) {
            ExFreePoolWithTag(blacklistProcess->Buffer, 'TAG1');
        }

        ExFreePoolWithTag(blacklistProcess, 'TAG1');
    }

    if (whitelistProcess) {
        if (whitelistProcess->Buffer) {
            ExFreePoolWithTag(whitelistProcess->Buffer, 'TAG2');
        }

        ExFreePoolWithTag(whitelistProcess, 'TAG2');
    }

    DbgPrint("MiniAV Driver Unloaded\n");
}


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = UnloadDriver;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoControl;

    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\MiniAV");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\MiniAV");

    PDEVICE_OBJECT DeviceObject;
    NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, AV_DEVICE_TYPE, 0, FALSE, &DeviceObject);

    if (!NT_SUCCESS(status)) {
        KdPrint(("IoCreateDevice failed with status: 0x%08X\n", status));
        return status;
    }

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("IoCreateSymbolicLink failed with status: 0x%08X\n", status));
        IoDeleteDevice(DeviceObject);
        return status;
    }

    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"PsGetProcessSectionBaseAddress");
    PsGetProcessSectionBaseAddress = (PSGETPROCESSSECTIONBASEADDRESS)MmGetSystemRoutineAddress(&routineName);
    if (PsGetProcessSectionBaseAddress == NULL) {
        KdPrint(("MmGetSystemRoutineAddress for PsGetProcessSectionBaseAddress failed\n"));
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(DeviceObject);
        return STATUS_UNSUCCESSFUL;
    }

    ExInitializeResourceLite(&listLock);
    KeInitializeMutex(&mutex, 0);

    KdPrint(("Registering ProcessNotifyRoutineEx\n"));
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, FALSE);
    if (!NT_SUCCESS(status)) {
        KdPrint(("PsSetCreateProcessNotifyRoutineEx failed with status: 0x%08X\n", status));
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(DeviceObject);
        return status;
    }

    KdPrint(("MiniAV Driver Loaded\n"));
    return status;
}