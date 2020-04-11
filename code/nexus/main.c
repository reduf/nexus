#include <stdio.h>
#include <stdbool.h>

#include "nexus.h"
#include <Shlwapi.h>

#include "mem.h"

static bool LaunchProcess(LPCWSTR Path, LPCWSTR Args, PPROCESS_INFORMATION ProcessInfo);

static void PathGetExeFullPath(LPWSTR Buffer, size_t BufferLength)
{
    DWORD Result = GetModuleFileNameW(NULL, Buffer, BufferLength);
    if (Result >= BufferLength)
        Buffer[0] = 0;
}

static void PathGetProgramDirectory(LPWSTR Buffer, size_t BufferLength)
{
    PathGetExeFullPath(Buffer, BufferLength);

    // Trim the filename from path to get the directory
    LPWSTR FileName = PathFindFileNameW(Buffer);
    if (FileName != Buffer)
        FileName[0] = 0;
}

int wmain(int argc, wchar_t *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: nexus <path> [options] [-- GuildWars arguments]\n");
        return 0;
    }

    LPWSTR Path = argv[1];
    for (int i = 0; i < argc; i++)
    {
        LPCWSTR args = argv[i];
        if (wcscmp(args, L"--"))
            break;
    }

    LPWSTR CmdLine = GetCommandLineW();
    LPWSTR ForwardedCmdLine = wcsstr(CmdLine, L" -- ");
    if (ForwardedCmdLine)
        ForwardedCmdLine += 4;

    PROCESS_INFORMATION ProcessInfo = {0};
    if (!LaunchProcess(Path, ForwardedCmdLine, &ProcessInfo))
        return 1;

    CloseHandles();

    //
    // Inject dll to avoid multiple process with write access to Gw.dat
    // We assume that nexusdll.dll is beside nexus.exe, but we compute
    // the absolute path to avoid any issues.
    //

    WCHAR DllPath[512];
    PathGetProgramDirectory(DllPath, ARRAY_SIZE(DllPath));
    wcscat_s(DllPath, ARRAY_SIZE(DllPath), L"nexusdll.dll");

    DWORD ExitCode;
    MEM_PROCESS MemProcess = {0};
    MemProcess.ProcessHandle = ProcessInfo.hProcess;
    MemInjectRemoteThread(&MemProcess, DllPath, &ExitCode);

    ResumeThread(ProcessInfo.hThread);

    return 0;
}

static bool LaunchProcess(LPCWSTR Path, LPCWSTR Args, PPROCESS_INFORMATION ProcessInfo)
{
    WCHAR CmdLine[512];

    Path = Path ? Path : L"";
    Args = Args ? Args : L"";

    if (swprintf(CmdLine, ARRAY_SIZE(CmdLine), L"\"%ls\" %ls", Path, Args) < 0)
    {
        fprintf(stderr, "Couldn't build the command line arguments with '\"%ls\" %ls'\n", Path, Args);
        return false;
    }

    STARTUPINFOW StartupInfo = {0};

    BOOL Success = CreateProcessW(
        NULL,
        CmdLine,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &StartupInfo,
        ProcessInfo);

    if (Success != TRUE)
    {
        fprintf(stderr, "CreateProcessW failed: %lu\n", GetLastError());
        return false;
    }

    return true;
}
