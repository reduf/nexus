#include "mem.h"

#include <assert.h>
#include <stdio.h>

#include <tlhelp32.h>

#ifndef UNREFERENCED_PARAMATER
#define UNREFERENCED_PARAMATER(P) (P)
#endif

#define RETRY_INTERVAL_MS   500
#define TOTAL_RETRY_TIME_MS 4000
#define RETRY_COUNT (TOTAL_RETRY_TIME_MS / RETRY_INTERVAL_MS)

BOOL MemOpenProcess(PMEM_PROCESS Process, DWORD ProcessId)
{
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
    if (hProc == NULL)
    {
        fprintf(stderr, "OpenProcess failed (%lu)\n", GetLastError());
        return FALSE;
    }

    Process->ProcessHandle = hProc;
    return TRUE;
}

BOOL MemCloseProcess(PMEM_PROCESS Process)
{
    HANDLE hProc = Process->ProcessHandle;
    if ((hProc != NULL) && (hProc != INVALID_HANDLE_VALUE))
        CloseHandle(hProc);

    Process->ProcessHandle = NULL;
    return TRUE;
}

SIZE_T MemEnumerateThreads(PMEM_PROCESS Process, PMEM_THREAD Threads, SIZE_T MaxThreads)
{
    if (MaxThreads == 0)
        return 0;

    DWORD ProcessId = GetProcessId(Process->ProcessHandle);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "CreateToolhelp32Snapshot failed (%lu)\n", GetLastError());
        return 0;
    }

    SIZE_T ReturnCount = 0;
    THREADENTRY32 ThreadEntry = {0};
    ThreadEntry.dwSize = sizeof(ThreadEntry);

    if (!Thread32First(hSnap, &ThreadEntry))
    {
        fprintf(stderr, "Thread32First failed (%lu)\n", GetLastError());
        return FALSE;
    }

    do
    {
        if (ThreadEntry.th32OwnerProcessID == ProcessId)
        {
            PMEM_THREAD Thread = &Threads[ReturnCount++];
            Thread->ThreadId = ThreadEntry.th32ThreadID;
            Thread->ThreadHandle = OpenThread(THREAD_ALL_ACCESS, 0, Thread->ThreadId);

            if (ReturnCount == MaxThreads)
                break;
        }
    } while (Thread32Next(hSnap, &ThreadEntry));

    CloseHandle(hSnap);
    return ReturnCount;
}

BOOL MemInjectWindowsHook(PMEM_PROCESS Process, LPCWSTR ImagePath)
{
    MEM_THREAD Thread;
    SIZE_T ThreadCount = MemEnumerateThreads(Process, &Thread, 1);
    if (ThreadCount == 0)
    {
        fprintf(stderr, "MemEnumerateThreads failed\n");
        return FALSE;
    }

    DWORD ThreadId = Thread.ThreadId;

    HMODULE hModule = LoadLibraryExW(ImagePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hModule == NULL)
    {
        fprintf(stderr, "LoadLibraryExW failed (%lu)\n", GetLastError());
        return FALSE;
    }

    LPVOID WndProc = GetProcAddress(hModule, "WndProc");
    if (WndProc == NULL)
    {
        fprintf(stderr, "GetProcAddress failed (%lu)\n", GetLastError());
        FreeLibrary(hModule);
        return FALSE;
    }

    HHOOK hHook = SetWindowsHookExW(
        WH_GETMESSAGE,
        WndProc,
        hModule,
        ThreadId);

    FreeLibrary(hModule);
    if (hHook == NULL)
    {
        fprintf(stderr, "SetWindowsHookExW failed (%lu)\n", GetLastError());
        return FALSE;
    }

    for (int i = 0; i < RETRY_COUNT; i++) {
        Sleep(RETRY_INTERVAL_MS);
        PostThreadMessageW(ThreadId, WM_USER + 432, 0, (LPARAM)hHook);
    }

    return TRUE;
}

static LPVOID MemGetLoadLibrary(void)
{
    HMODULE Kernel32 = GetModuleHandleW(L"Kernel32.dll");
    if (Kernel32 == NULL)
    {
        fprintf(stderr, "GetModuleHandleW failed (%lu)\n", GetLastError());
        return NULL;
    }

    LPVOID LoadLibraryWPtr = GetProcAddress(Kernel32, "LoadLibraryW");
    if (LoadLibraryWPtr == NULL)
    {
        fprintf(stderr, "GetProcAddress failed (%lu)\n", GetLastError());
        return NULL;
    }

    return LoadLibraryWPtr;
}

BOOL MemInjectRemoteThread(PMEM_PROCESS Process, LPCWSTR ImagePath, LPDWORD lpExitCode)
{
    *lpExitCode = 0;

    HANDLE ProcessHandle = Process->ProcessHandle;
    if (ProcessHandle == NULL)
    {
        fprintf(stderr, "Can't inject a dll in a process which is not open\n");
        return FALSE;
    }

    LPVOID LoadLibraryWPtr = MemGetLoadLibrary();
    if (LoadLibraryWPtr == NULL)
        return FALSE;

    size_t ImagePathLength = wcslen(ImagePath);
    size_t ImagePathSize = (ImagePathLength * 2) + 2;

    LPVOID ImagePathAddress = VirtualAllocEx(
        ProcessHandle,
        NULL,
        ImagePathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (ImagePathAddress == NULL)
    {
        fprintf(stderr, "VirtualAllocEx failed (%lu)\n", GetLastError());
        return FALSE;
    }

    SIZE_T BytesWritten;
    BOOL Success = WriteProcessMemory(
        ProcessHandle,
        ImagePathAddress,
        ImagePath,
        ImagePathSize,
        &BytesWritten);

    if (!Success || (ImagePathSize != BytesWritten))
    {
        fprintf(stderr, "WriteProcessMemory failed (%lu)\n", GetLastError());
        VirtualFreeEx(ProcessHandle, ImagePathAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    DWORD ThreadId;
    HANDLE hThread = CreateRemoteThreadEx(
        ProcessHandle,
        NULL,
        0,
        LoadLibraryWPtr,
        ImagePathAddress,
        0,
        NULL,
        &ThreadId);

    if (hThread == NULL)
    {
        fprintf(stderr, "CreateRemoteThreadEx failed (%lu)\n", GetLastError());
        return FALSE;
    }

    DWORD Reason = WaitForSingleObject(hThread, INFINITE);
    if (Reason != WAIT_OBJECT_0)
    {
        fprintf(stderr, "WaitForSingleObject failed {reason: %lu, error: %lu}\n", Reason, GetLastError());
        CloseHandle(hThread);
        return FALSE;
    }

    VirtualFreeEx(ProcessHandle, ImagePathAddress, 0, MEM_RELEASE);

    DWORD ExitCode;
    Success = GetExitCodeThread(hThread, &ExitCode);
    CloseHandle(hThread);

    if (Success == FALSE)
    {
        fprintf(stderr, "GetExitCodeThread failed (%lu)\n", GetLastError());
        return FALSE;
    }

    *lpExitCode = ExitCode;
    return TRUE;
}
