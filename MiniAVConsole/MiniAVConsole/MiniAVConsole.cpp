#include <windows.h>
#include <stdio.h>

#define AV_DEVICE_TYPE 0x8000
#define IOCTL_INIT CTL_CODE(AV_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CHECK_INIT CTL_CODE(AV_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BLACKLIST_PROCESS CTL_CODE(AV_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WHITELIST_PROCESS CTL_CODE(AV_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DUMP_PROCESS CTL_CODE(AV_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KILL_PROCESS CTL_CODE(AV_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)


typedef struct _DUMP_REQUEST {
    ULONG pid;
    ULONG size;
    WCHAR dumpfile[260];
} DUMP_REQUEST, * PDUMP_REQUEST;



void PrintLastError(const wchar_t* customMessage) {
    DWORD error = GetLastError();
    LPVOID errorMessage;

    // Format the error message
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&errorMessage,
        0,
        NULL
    );

    // Print the custom message and the error message
    wprintf(L"%s: %s\n", customMessage, (LPWSTR)errorMessage);

    // Free the buffer allocated by FormatMessage
    LocalFree(errorMessage);
}


BOOL CheckInitStatus() {
    HANDLE hDevice = CreateFile(L"\\\\.\\MiniAV", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        wprintf(L"Error: Could not open MiniAV device\n");
        return FALSE;
    }

    BOOL isInitialized = FALSE;
    DWORD bytesReturned;
    BOOL result = DeviceIoControl(hDevice, IOCTL_CHECK_INIT, NULL, 0, &isInitialized, sizeof(isInitialized), &bytesReturned, NULL);

    CloseHandle(hDevice);

    if (!result) {
        PrintLastError(L"ERROR: DeviceIoControl failed");
        return FALSE;
    }

    return isInitialized;
}


BOOL SendIoctlCommand(DWORD ioctlCode, LPVOID inputBuffer, DWORD inputBufferSize) {
    HANDLE hDevice = CreateFile(L"\\\\.\\MiniAV", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        wprintf(L"Error: Could not open MiniAV device\n");
        return FALSE;
    }

    DWORD bytesReturned;
    BOOL result = DeviceIoControl(hDevice, ioctlCode, inputBuffer, inputBufferSize, NULL, 0, &bytesReturned, NULL);

    if (!result) {
        PrintLastError(L"ERROR: DeviceIoControl failed");
    }

    CloseHandle(hDevice);
    return result;
}


void printUsage() {
    wprintf(L"Usage:\n"
        L"> MiniAVConsole.exe -init\n"
        L"> MiniAVConsole.exe -[blacklist|whitelist] <filename.exe>\n"
        L"> MiniAVConsole.exe -dump <pid> -size <n> -file <dumpfile>\n"
        L"> MiniAVConsole.exe -kill <pid>\n");
}


void ConvertDosPathToNtPath(const wchar_t* dosPath, wchar_t* ntPath) {
    wcscpy_s(ntPath, 260, L"\\??\\");
    wcscat_s(ntPath, 260, dosPath);
}



int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        printUsage();
        return 1;
    }

    const wchar_t* command = argv[1];
    BOOL result = FALSE;

    if (wcscmp(command, L"-init") == 0 && argc == 2) {
        result = SendIoctlCommand(IOCTL_INIT, NULL, 0);
        if (result) {
            wprintf(L"AV successfully initialized!\n");
        }
        else {
            PrintLastError(L"ERROR: AV not initialized!");
        }
    }

    else if (!CheckInitStatus()) {
        wprintf(L"You must initialize the AV. run:\n"
                L"> MiniAVConsole.exe -init\n");
        return 1;
    }

    else if (wcscmp(command, L"-blacklist") == 0 && argc == 3) {
        const wchar_t* filename = argv[2];
        result = SendIoctlCommand(IOCTL_BLACKLIST_PROCESS, (LPVOID)filename, (wcslen(filename) + 1) * sizeof(wchar_t));
        if (result) {
            wprintf(L"Process %s blocked successfully\n", filename);
        }
        else {
            PrintLastError(L"ERROR: Could not block process!\n");
        }
    }

    else if (wcscmp(command, L"-whitelist") == 0 && argc == 3) {
        const wchar_t* filename = argv[2];
        result = SendIoctlCommand(IOCTL_WHITELIST_PROCESS, (LPVOID)filename, (wcslen(filename) + 1) * sizeof(wchar_t));
        if (result) {
            wprintf(L"Process %s whitelisted successfully\n", filename);
        }
        else {
            PrintLastError(L"ERROR: Could not whitelist process!\n");
        }
    }

    else if (wcscmp(command, L"-dump") == 0 && argc == 7) {
        DUMP_REQUEST dumpRequest;
        dumpRequest.pid = _wtoi(argv[2]);
        for (int i = 3; i < argc; i += 2) {
            if (wcscmp(argv[i], L"-size") == 0) {
                dumpRequest.size = _wtoi(argv[i + 1]);
            }
            else if (wcscmp(argv[i], L"-file") == 0) {
                ConvertDosPathToNtPath(argv[i + 1], dumpRequest.dumpfile);
            }
        }

        result = SendIoctlCommand(IOCTL_DUMP_PROCESS, &dumpRequest, sizeof(DUMP_REQUEST));
        if (result) {
            wprintf(L"Dump process memory successfully: pid=%lu, size=%lu, dumpfile=%ws\n", dumpRequest.pid, dumpRequest.size, dumpRequest.dumpfile);
        }
        else {
            PrintLastError(L"ERROR: Could not dump process memory!\n");
        }
    }

    else if (wcscmp(command, L"-kill") == 0 && argc == 3) {
        ULONG pid = _wtoi(argv[2]);
        result = SendIoctlCommand(IOCTL_KILL_PROCESS, &pid, sizeof(ULONG));
        if (result) {
            wprintf(L"Killed Process %lu successfully\n", pid);
        }
        else {
            PrintLastError(L"ERROR: Could not kill process!\n");
        }
    }

    else {
        printUsage();
        return 1;
    }

    return 0;
}
