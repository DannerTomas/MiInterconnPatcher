#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <string.h>
#include <locale.h>

#pragma comment(lib, "psapi.lib")

ULONG_PTR GetModuleBaseAddress(DWORD processId, const WCHAR* moduleName);
DWORD FindFunctionRVA(HANDLE processHandle, ULONG_PTR baseAddress);
BOOL patch_check(DWORD processId, ULONG_PTR baseAddress, DWORD rvaOffset);
void log_console(const wchar_t* format, ...);

BYTE functionSignature[] = {
    0x4C, 0x8B, 0xDC,
    0x49, 0x89, 0x5B, 0x08,
    0x49, 0x89, 0x73, 0x10,
    0x57,
    0x48, 0x81, 0xEC, 0xC0, 0x00, 0x00, 0x00,
    0x48, 0x8B, 0x05
};

BYTE signatureMask[] = {
    0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0x00
};

BYTE simpleSignature[] = {
        0x4C, 0x8B, 0xDC,
        0x49, 0x89, 0x5B, 0x08,
        0x49, 0x89, 0x73, 0x10,
        0x57,
        0x48, 0x81, 0xEC
};

BYTE simpleMask[] = {
    0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF,
    0xFF, 0xFF, 0xFF
};

ULONG_PTR FindPatternInMemory(HANDLE processHandle, ULONG_PTR startAddress, SIZE_T size,
    const BYTE* pattern, const BYTE* mask, SIZE_T patternSize)
{
    BYTE* buffer = (BYTE*)malloc(size);
    if (!buffer)
        return 0;

    SIZE_T bytesRead;
    if (!ReadProcessMemory(processHandle, (LPCVOID)startAddress, (LPVOID)buffer, size, &bytesRead))
    {
        free(buffer);
        return 0;
    }

    for (SIZE_T i = 0; i <= bytesRead - patternSize; i++)
    {
        BOOL found = TRUE;
        for (SIZE_T j = 0; j < patternSize; j++)
        {
            if (mask && mask[j] == 0x00)
                continue;

            if (buffer[i + j] != pattern[j])
            {
                found = FALSE;
                break;
            }
        }

        if (found)
        {
            ULONG_PTR result = startAddress + i;
            free(buffer);
            return result;
        }
    }

    free(buffer);
    return 0;
}

DWORD FindFunctionRVA(HANDLE processHandle, ULONG_PTR baseAddress)
{
    MODULEINFO moduleInfo;
    if (!GetModuleInformation(processHandle, (HMODULE)baseAddress, &moduleInfo, sizeof(moduleInfo)))
    {
        log_console(L"Failed to get module information. Error code: %lu", GetLastError());
        return 0;
    }

    log_console(L"Module base address: 0x%llX", (unsigned long long)baseAddress);
    log_console(L"Module size: 0x%llX", (unsigned long long)moduleInfo.SizeOfImage);

    log_console(L"Searching for function signature...");

    ULONG_PTR functionAddress = FindPatternInMemory(processHandle, baseAddress, moduleInfo.SizeOfImage,
        functionSignature, signatureMask, sizeof(functionSignature));

    if (functionAddress != 0)
    {
        log_console(L"Found function address: 0x%llX", (unsigned long long)functionAddress);

        DWORD rva = (DWORD)(functionAddress - baseAddress);
        log_console(L"Calculated RVA: 0x%lX", rva);

        DWORD expectedRva = 0xCCA40;
        DWORD diff = (rva > expectedRva) ? (rva - expectedRva) : (expectedRva - rva);

        if (diff > 0x100)
        {
            log_console(L"Warning: Found RVA (0x%lX) differs significantly from expected (0x%lX) by 0x%lX", rva, expectedRva, diff);
            log_console(L"Signature matched, using found RVA");
        }

        return rva;
    }

    log_console(L"Full signature not found, trying simplified signature...");

    functionAddress = FindPatternInMemory(processHandle, baseAddress, moduleInfo.SizeOfImage,
        simpleSignature, simpleMask, sizeof(simpleSignature));

    if (functionAddress != 0)
    {
        log_console(L"Found function address using simplified signature: 0x%llX", (unsigned long long)functionAddress);

        DWORD rva = (DWORD)(functionAddress - baseAddress);
        log_console(L"Calculated RVA: 0x%lX", rva);

        return rva;
    }

    log_console(L"Function signature not found");
    return 0;
}

int wmain(int argc, wchar_t* argv[])
{
    setlocale(LC_CTYPE, "CHS");

    if (argc < 2)
    {
        wprintf(L"Usage: %s <exe path to launch> [manual RVA offset (optional)]\n", argv[0]);
        wprintf(L"Example: %s D:\\JYWn_PcContinuity_main_xxx.exe\n", argv[0]);
        wprintf(L"Example with RVA: %s D:\\JYWn_PcContinuity_main_xxx.exe 0xCCA40\n", argv[0]);
        return 1;
    }

    const WCHAR* exePath = argv[1];
    DWORD manualRva = 0;

    if (argc >= 3)
    {
        manualRva = wcstoul(argv[2], NULL, 16);
        log_console(L"Using manually specified RVA: 0x%lX", manualRva);
    }

    log_console(L"Launching: %s", exePath);

    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    WCHAR exeDir[MAX_PATH] = { 0 };
    wcscpy_s(exeDir, MAX_PATH, exePath);
    WCHAR* lastSlash = wcsrchr(exeDir, L'\\');
    if (lastSlash)
    {
        *lastSlash = L'\0';
    }
    else
    {
        GetCurrentDirectoryW(MAX_PATH, exeDir);
    }

    BOOL success = CreateProcessW( exePath, NULL, NULL, NULL, FALSE, NULL, NULL, exeDir, &si, &pi);

    if (!success)
    {
        log_console(L"Failed to launch process. Error code: %lu", GetLastError());
        return 1;
    }

    log_console(L"Process launched, PID: %lu", pi.dwProcessId);

    const WCHAR* fileName = wcsrchr(exePath, L'\\');
    if (fileName) fileName++;
    else fileName = exePath;

    ULONG_PTR baseAddress = GetModuleBaseAddress(pi.dwProcessId, fileName);
    if (baseAddress == 0)
    {
        log_console(L"Failed to get module base address");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    log_console(L"Actual loaded base address: 0x%llX", (unsigned long long)baseAddress);

    DWORD functionRva = 0;

    if (manualRva != 0)
    {
        functionRva = manualRva;
        log_console(L"Using manually specified RVA: 0x%lX", manualRva);
    }
    else
    {
        log_console(L"Automatically searching for function RVA...");
        functionRva = FindFunctionRVA(pi.hProcess, baseAddress);

        if (functionRva == 0)
        {
            log_console(L"Automatic search failed, using default RVA: 0xCCA40");
            functionRva = 0xCCA40;
        }
    }

    log_console(L"Final function RVA used: 0x%lX", functionRva);

    log_console(L"Patching function...");
    if (patch_check(pi.dwProcessId, baseAddress, functionRva))
    {
        log_console(L"Successfully patched check function");
    }
    else
    {
        log_console(L"Failed to patch function. Error code: %lu", GetLastError());
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    log_console(L"Patch successfully, now enjoy it :)");

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}

ULONG_PTR GetModuleBaseAddress(DWORD processId, const WCHAR* moduleName)
{
    ULONG_PTR baseAddress = 0;
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);

    if (processHandle)
    {
        HMODULE hModules[1024];
        DWORD cbNeeded;

        if (EnumProcessModules(processHandle, hModules, sizeof(hModules), &cbNeeded))
        {
            WCHAR moduleNameBuffer[MAX_PATH];

            for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++)
            {
                if (GetModuleFileNameExW(processHandle, hModules[i], moduleNameBuffer, MAX_PATH))
                {
                    WCHAR* fileName = wcsrchr(moduleNameBuffer, L'\\');
                    if (fileName) fileName++;
                    else fileName = moduleNameBuffer;

                    if (_wcsicmp(fileName, moduleName) == 0)
                    {
                        baseAddress = (ULONG_PTR)hModules[i];
                        break;
                    }
                }
            }
        }

        CloseHandle(processHandle);
    }

    return baseAddress;
}

BOOL patch_check(DWORD processId, ULONG_PTR baseAddress, DWORD rvaOffset)
{
    ULONG_PTR functionAddress = baseAddress + rvaOffset;
    log_console(L"Function actual address: 0x%llX", (unsigned long long)functionAddress);

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!processHandle)
    {
        log_console(L"Failed to open process. Error code: %lu", GetLastError());
        return FALSE;
    }

    BYTE originalCode[16] = { 0 };
    SIZE_T bytesRead = 0;
    if (ReadProcessMemory(processHandle, (LPCVOID)functionAddress, (LPVOID)originalCode, sizeof(originalCode), &bytesRead))
    {
        wprintf(L"[Mi_InterConn_Patcher] Original code: ");
        for (SIZE_T i = 0; i < min(bytesRead, 16); i++)
        {
            wprintf(L"%02X ", originalCode[i]);
        }
        wprintf(L"\n");
    }
    else
    {
        log_console(L"Failed to read original code. Error code: %lu", GetLastError());
        CloseHandle(processHandle);
        return FALSE;
    }

    BYTE patchCode[] = { 0x31, 0xC0, 0xFF, 0xC0, 0xC3 };

    DWORD oldProtect = 0;
    if (!VirtualProtectEx(processHandle, (LPVOID)functionAddress, sizeof(patchCode), PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        log_console(L"Failed to change memory protection. Error code: %lu", GetLastError());
        CloseHandle(processHandle);
        return FALSE;
    }

    SIZE_T bytesWritten = 0;
    BOOL result = WriteProcessMemory(processHandle, (LPVOID)functionAddress, (LPCVOID)patchCode, sizeof(patchCode), &bytesWritten);

    if (result)
    {
        log_console(L"Successfully written %zu bytes", bytesWritten);

        BYTE verifyCode[sizeof(patchCode)] = { 0 };
        if (ReadProcessMemory(processHandle, (LPCVOID)functionAddress, (LPVOID)verifyCode, sizeof(verifyCode), NULL))
        {
            wprintf(L"[Mi_InterConn_Patcher] Verify write: ");
            for (SIZE_T i = 0; i < sizeof(patchCode); i++)
            {
                wprintf(L"%02X ", verifyCode[i]);
            }
            wprintf(L"\n");

            BOOL match = TRUE;
            for (SIZE_T i = 0; i < sizeof(patchCode); i++)
            {
                if (verifyCode[i] != patchCode[i])
                {
                    match = FALSE;
                    break;
                }
            }

            if (match)
            {
                log_console(L"Write verification successful!");
            }
            else
            {
                log_console(L"Warning: Write verification failed");
            }
        }
        else
        {
            log_console(L"Unable to verify write");
        }
    }
    else
    {
        log_console(L"Failed to write memory. Error code: %lu", GetLastError());
    }

    DWORD tempProtect;
    VirtualProtectEx(processHandle, (LPVOID)functionAddress, sizeof(patchCode), oldProtect, &tempProtect);

    CloseHandle(processHandle);
    return result;
}

void log_console(const wchar_t* format, ...)
{
    va_list args;
    va_start(args, format);
    wprintf(L"[Mi_InterConn_Patcher] ");
    vwprintf(format, args);
    wprintf(L"\n");
    va_end(args);
}