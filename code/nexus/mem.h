#pragma once

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
# define NOMINMAX
#endif

#include <Windows.h>

typedef struct _MEM_PROCESS {
    HANDLE ProcessHandle;
} MEM_PROCESS, *PMEM_PROCESS;

typedef struct _MEM_THREAD {
    DWORD  ThreadId;
    HANDLE ThreadHandle;
} MEM_THREAD, *PMEM_THREAD;

BOOL MemOpenProcess(PMEM_PROCESS Process, DWORD ProcessId);
BOOL MemCloseProcess(PMEM_PROCESS Process);

SIZE_T MemEnumerateThreads(PMEM_PROCESS Process, PMEM_THREAD Threads, SIZE_T ThreadCount);

BOOL MemInjectWindowsHook(PMEM_PROCESS Process, LPCWSTR ImagePath);
BOOL MemInjectRemoteThread(PMEM_PROCESS Process, LPCWSTR ImagePath, LPDWORD lpExitCode);
