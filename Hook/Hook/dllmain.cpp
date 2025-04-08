#include "InjectHook.h"
#include <Windows.h>
#include <map>
#include <time.h>
#include <set>
#include <string>
#include <fstream>
#include <tlhelp32.h>
#include <psapi.h>
#include <Shlobj.h>


HANDLE g_hToken = NULL;
HANDLE g_hMonitorThread = NULL;
BOOL g_bExitThread = FALSE;

// Function to get the process token
HANDLE GetProcessToken() {
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return hToken;
    }
    return NULL;
}

// Function to compare tokens
BOOL IsTokenChanged() {
    HANDLE hNewToken = GetProcessToken();
    if (!hNewToken) return FALSE;

    // Compare token handles
    BOOL changed = !DuplicateHandle(GetCurrentProcess(), g_hToken, GetCurrentProcess(), NULL, 0, FALSE, DUPLICATE_SAME_ACCESS);

    CloseHandle(hNewToken);
    return changed;
}



LPVOID wf;
LPVOID nwf;
LPVOID copyFileA;
LPVOID copyFileW;
LPVOID moveFileA;
LPVOID moveFileW;

#define MAX_WRITE_COUNT 6
#define TIME_LIMIT 1

typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef _Function_class_(IO_APC_ROUTINE)
VOID NTAPI IO_APC_ROUTINE(
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved
);

typedef IO_APC_ROUTINE* PIO_APC_ROUTINE;


typedef NTSTATUS(NTAPI* pNtWriteFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
    );

std::string GetProcessName(DWORD pid) {
    char processName[MAX_PATH] = "Unknown";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        GetModuleFileNameExA(hProcess, NULL, processName, MAX_PATH);
        CloseHandle(hProcess);
    }
    return std::string(processName);
}

void WriteSecurityBreachFile(int mode = 0) {
    DWORD pid = GetCurrentProcessId();
    char desktopPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath))) {
        std::string filePath = std::string(desktopPath) + "\\SECURITY_BREACH.txt";
        std::ofstream outFile(filePath);
        if (outFile.is_open()) {
            if (mode == 0) {
                outFile << "DETECTED RANSOMWARE RUNNING IN THE SYSTEM! CALL YOUR IT MANAGER ASAP!\n";
                outFile << "Details: " << pid << " " << GetProcessName(pid) << "\n";
                
            }
            else if (mode == 1) {
                outFile << "DETECTED PRIVILEGE ESCALATION EXPLOIT! CALL YOUR IT MANAGER ASAP!\n";
                outFile << "Details: " << pid << " " << GetProcessName(pid) << "\n";
            }

            outFile.close();
        }
    }
}

// Thread function to monitor token changes
DWORD WINAPI TokenMonitorThread(LPVOID lpParam) {
    while (!g_bExitThread) {
        if (IsTokenChanged()) {
            WriteSecurityBreachFile(1);
            TerminateProcess(GetCurrentProcess(), 0);
        }
        Sleep(1000);  // Check every 1 second
    }
    return 0;
}


int write_count;
time_t last_write_time;

int tracker_count = 0;
std::set<std::string> accessed_files;
std::set<std::wstring> accessed_filesW;
CHAR tmp[MAX_PATH];

BOOL hWriteFile(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
) {
    HookLib::RemoveHook(wf);

    DWORD pid = GetCurrentProcessId();
    char file_path[MAX_PATH];
    if (GetFinalPathNameByHandleA(hFile, file_path, MAX_PATH, FILE_NAME_OPENED)) {
        if (strstr(file_path, ".txt") ||
            strstr(file_path, ".docx") ||
            strstr(file_path, ".xlsx") ||
            strstr(file_path, ".pptx") ||
            strstr(file_path, ".pdf") ||
            strstr(file_path, ".jpg") ||
            strstr(file_path, ".jpeg") ||
            strstr(file_path, ".png") ||
            strstr(file_path, ".gif") ||
            strstr(file_path, ".bmp") ||
            strstr(file_path, ".mp3") ||
            strstr(file_path, ".wav") ||
            strstr(file_path, ".zip") ||
            strstr(file_path, ".rar") ||
            strstr(file_path, ".7z") ||
            strstr(file_path, ".tar") ||
            strstr(file_path, ".bak") ||
            strstr(file_path, ".doc") ||
            strstr(file_path, ".xls") ||
            strstr(file_path, ".ppt") ||
            strstr(file_path, ".mdb") ||
            strstr(file_path, ".sqlite") ||
            strstr(file_path, ".json") ||
            strstr(file_path, ".xml") ||
            strstr(file_path, ".mp4") ||
            strstr(file_path, ".mov") ||
            strstr(file_path, ".avi") ||
            strstr(file_path, ".mkv") ||
            strstr(file_path, ".flv") ||
            strstr(file_path, ".wmv") ||
            strstr(file_path, ".webm") ||
            strstr(file_path, ".aac") ||
            strstr(file_path, ".ogg") ||
            strstr(file_path, ".m4a") ||
            strstr(file_path, ".odt") ||
            strstr(file_path, ".ods") ||
            strstr(file_path, ".odp") ||
            strstr(file_path, ".onetoc") ||
            strstr(file_path, ".docm") ||
            strstr(file_path, ".xlsm") ||
            strstr(file_path, ".pptm") ||
            strstr(file_path, ".xml") ||
            strstr(file_path, ".vsd") ||
            strstr(file_path, ".vsdx") ||
            strstr(file_path, ".eml"))
        {

            
            auto it = accessed_files.find(file_path);
            /*
            if (!(it != accessed_files.end())) {

                CHAR pat[1500];

                snprintf(pat, 1500, "copy \"%s\" \"%sRecoverFiles\"", file_path, tmp);
                system(pat);

            }*/

            accessed_files.insert(file_path);
            time_t current_time = time(NULL);

            if (last_write_time == 0) {
                last_write_time = current_time;
            }

            // Reset the count after each TIME_LIMIT seconds
            if (difftime(current_time, last_write_time) > TIME_LIMIT) {
                write_count = 0;
                accessed_files.clear();
                last_write_time = current_time;
            }

            write_count++;

            if ((write_count >= MAX_WRITE_COUNT && accessed_files.size() >= MAX_WRITE_COUNT)) {

                // LockBit 3.0 can use threads to continue encryption / taskkill events. That's why I prefer directly killin' the malicious process
                //MessageBoxA(NULL, "SYSTEM IS INFECTED BY RANSOMWARE! PLEASE DO NOT TOUCH ANYTHING AND CALL YOUR IT NOW", "Anti-Ransomware", MB_ICONERROR | MB_OK);
                WriteSecurityBreachFile();
                TerminateProcess(OpenProcess(PROCESS_TERMINATE, FALSE, pid), 0);
            }



        }
    }

    BOOL res = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    InstallHook(wf, &hWriteFile, HookLib::JMP_LONG);
    return res;
}

#include <unordered_set>

typedef NTSTATUS(NTAPI* NtWriteFile_t)(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
    );

NtWriteFile_t OriginalNtWriteFile = nullptr;

#define MAX_WRITE_COUNT 4
#define TIME_LIMIT 2

BOOL GetFilePathFromHandle(HANDLE hFile, char* filePath, DWORD size) {
    return GetFinalPathNameByHandleA(hFile, filePath, size, FILE_NAME_OPENED) > 0;
}


NTSTATUS NTAPI hNtWriteFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
) {
    char file_path[MAX_PATH] = { 0 };
    HookLib::RemoveHook(nwf);
    OriginalNtWriteFile = (NtWriteFile_t)nwf;
    

    if (GetFilePathFromHandle(FileHandle, file_path, MAX_PATH)) {
        if (strstr(file_path, ".txt") ||
            strstr(file_path, ".docx") ||
            strstr(file_path, ".xlsx") ||
            strstr(file_path, ".pptx") ||
            strstr(file_path, ".pdf") ||
            strstr(file_path, ".jpg") ||
            strstr(file_path, ".jpeg") ||
            strstr(file_path, ".png") ||
            strstr(file_path, ".gif") ||
            strstr(file_path, ".bmp") ||
            strstr(file_path, ".mp3") ||
            strstr(file_path, ".wav") ||
            strstr(file_path, ".zip") ||
            strstr(file_path, ".rar") ||
            strstr(file_path, ".7z") ||
            strstr(file_path, ".tar") ||
            strstr(file_path, ".bak") ||
            strstr(file_path, ".doc") ||
            strstr(file_path, ".xls") ||
            strstr(file_path, ".ppt") ||
            strstr(file_path, ".mdb") ||
            strstr(file_path, ".sqlite") ||
            strstr(file_path, ".json") ||
            strstr(file_path, ".xml") ||
            strstr(file_path, ".mp4") ||
            strstr(file_path, ".mov") ||
            strstr(file_path, ".avi") ||
            strstr(file_path, ".mkv") ||
            strstr(file_path, ".flv") ||
            strstr(file_path, ".wmv") ||
            strstr(file_path, ".webm") ||
            strstr(file_path, ".aac") ||
            strstr(file_path, ".ogg") ||
            strstr(file_path, ".m4a") ||
            strstr(file_path, ".odt") ||
            strstr(file_path, ".ods") ||
            strstr(file_path, ".odp") ||
            strstr(file_path, ".onetoc") ||
            strstr(file_path, ".docm") ||
            strstr(file_path, ".xlsm") ||
            strstr(file_path, ".pptm") ||
            strstr(file_path, ".xml") ||
            strstr(file_path, ".vsd") ||
            strstr(file_path, ".vsdx") ||
            strstr(file_path, ".eml"))
        {
               /* if (accessed_files.find(file_path) == accessed_files.end()) {
                    char backup_cmd[1500];
                    snprintf(backup_cmd, sizeof(backup_cmd), "copy \"%s\" \"%sRecoverFiles\"", file_path, tmp);
                    system(backup_cmd);
                }*/

                accessed_files.insert(file_path);
                time_t current_time = time(NULL);

                if (last_write_time == 0) last_write_time = current_time;

                if (difftime(current_time, last_write_time) > TIME_LIMIT) {
                    write_count = 0;
                    accessed_files.clear();
                    last_write_time = current_time;
                }

                write_count++;

                if (write_count >= MAX_WRITE_COUNT && accessed_files.size() >= MAX_WRITE_COUNT) {
                    WriteSecurityBreachFile();
                    TerminateProcess(OpenProcess(PROCESS_TERMINATE, FALSE, GetCurrentProcessId()), 0);
                }
        }
    }
    NTSTATUS res = OriginalNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    HookLib::InstallHook(nwf, hNtWriteFile, HookLib::JMP_LONG);
    return res;
}




BOOL hCopyFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists) {
    HookLib::RemoveHook(copyFileA);

    if (strstr(lpExistingFileName, ".txt") || strstr(lpExistingFileName, ".docx") ||
        strstr(lpExistingFileName, ".xlsx") || strstr(lpExistingFileName, ".pptx") ||
        strstr(lpExistingFileName, ".pdf") || strstr(lpExistingFileName, ".jpg") ||
        strstr(lpExistingFileName, ".jpeg") || strstr(lpExistingFileName, ".png") ||
        strstr(lpExistingFileName, ".gif") || strstr(lpExistingFileName, ".bmp") ||
        strstr(lpExistingFileName, ".mp3") || strstr(lpExistingFileName, ".wav") ||
        strstr(lpExistingFileName, ".zip") || strstr(lpExistingFileName, ".rar") ||
        strstr(lpExistingFileName, ".7z") || strstr(lpExistingFileName, ".tar") ||
        strstr(lpExistingFileName, ".bak") || strstr(lpExistingFileName, ".doc") ||
        strstr(lpExistingFileName, ".xls") || strstr(lpExistingFileName, ".ppt") ||
        strstr(lpExistingFileName, ".mdb") || strstr(lpExistingFileName, ".sqlite") ||
        strstr(lpExistingFileName, ".json") || strstr(lpExistingFileName, ".xml") ||
        strstr(lpExistingFileName, ".mp4") || strstr(lpExistingFileName, ".mov") ||
        strstr(lpExistingFileName, ".avi") || strstr(lpExistingFileName, ".mkv") ||
        strstr(lpExistingFileName, ".flv") || strstr(lpExistingFileName, ".wmv") ||
        strstr(lpExistingFileName, ".webm") || strstr(lpExistingFileName, ".aac") ||
        strstr(lpExistingFileName, ".ogg") || strstr(lpExistingFileName, ".m4a") ||
        strstr(lpExistingFileName, ".odt") || strstr(lpExistingFileName, ".ods") ||
        strstr(lpExistingFileName, ".odp") || strstr(lpExistingFileName, ".onetoc") ||
        strstr(lpExistingFileName, ".docm") || strstr(lpExistingFileName, ".xlsm") ||
        strstr(lpExistingFileName, ".pptm") || strstr(lpExistingFileName, ".xml") ||
        strstr(lpExistingFileName, ".vsd") || strstr(lpExistingFileName, ".vsdx") ||
        strstr(lpExistingFileName, ".eml")) {

        auto it = accessed_files.find(lpExistingFileName);
        /*        if (!(it != accessed_files.end())) {

            CHAR pat[MAX_PATH];

            snprintf(pat, MAX_PATH, "copy \"%s\" \"%sRecoverFiles\"", lpExistingFileName, tmp);
            system(pat);

        }*/


        accessed_files.insert(lpExistingFileName);

        time_t current_time = time(NULL);
        if (last_write_time == 0) { last_write_time = current_time; }

        if (difftime(current_time, last_write_time) > TIME_LIMIT) {
            write_count = 0;
            accessed_files.clear();
            last_write_time = current_time;
        }

        write_count++;

        if ((write_count >= MAX_WRITE_COUNT && accessed_files.size() >= MAX_WRITE_COUNT)) {
            //MessageBoxA(NULL, "SYSTEM IS INFECTED BY RANSOMWARE! PLEASE DO NOT TOUCH ANYTHING AND CALL YOUR IT NOW", "Anti-Ransomware", MB_ICONERROR | MB_OK);
            WriteSecurityBreachFile();
            TerminateProcess(OpenProcess(PROCESS_TERMINATE, FALSE, GetCurrentProcessId()), 0);
        }
    }

    BOOL res = CopyFileA(lpExistingFileName, lpNewFileName, bFailIfExists);
    InstallHook(copyFileA, &hCopyFileA, HookLib::JMP_LONG);
    return res;
}

BOOL hCopyFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists) {
    HookLib::RemoveHook(copyFileW);


    if (wcsstr(lpExistingFileName, L".txt") || wcsstr(lpExistingFileName, L".docx") ||
        wcsstr(lpExistingFileName, L".xlsx") || wcsstr(lpExistingFileName, L".pptx") ||
        wcsstr(lpExistingFileName, L".pdf") || wcsstr(lpExistingFileName, L".jpg") ||
        wcsstr(lpExistingFileName, L".jpeg") || wcsstr(lpExistingFileName, L".png") ||
        wcsstr(lpExistingFileName, L".gif") || wcsstr(lpExistingFileName, L".bmp") ||
        wcsstr(lpExistingFileName, L".mp3") || wcsstr(lpExistingFileName, L".wav") ||
        wcsstr(lpExistingFileName, L".zip") || wcsstr(lpExistingFileName, L".rar") ||
        wcsstr(lpExistingFileName, L".7z") || wcsstr(lpExistingFileName, L".tar") ||
        wcsstr(lpExistingFileName, L".bak") || wcsstr(lpExistingFileName, L".doc") ||
        wcsstr(lpExistingFileName, L".xls") || wcsstr(lpExistingFileName, L".ppt") ||
        wcsstr(lpExistingFileName, L".mdb") || wcsstr(lpExistingFileName, L".sqlite") ||
        wcsstr(lpExistingFileName, L".json") || wcsstr(lpExistingFileName, L".xml") ||
        wcsstr(lpExistingFileName, L".mp4") || wcsstr(lpExistingFileName, L".mov") ||
        wcsstr(lpExistingFileName, L".avi") || wcsstr(lpExistingFileName, L".mkv") ||
        wcsstr(lpExistingFileName, L".flv") || wcsstr(lpExistingFileName, L".wmv") ||
        wcsstr(lpExistingFileName, L".webm") || wcsstr(lpExistingFileName, L".aac") ||
        wcsstr(lpExistingFileName, L".ogg") || wcsstr(lpExistingFileName, L".m4a") ||
        wcsstr(lpExistingFileName, L".odt") || wcsstr(lpExistingFileName, L".ods") ||
        wcsstr(lpExistingFileName, L".odp") || wcsstr(lpExistingFileName, L".onetoc") ||
        wcsstr(lpExistingFileName, L".docm") || wcsstr(lpExistingFileName, L".xlsm") ||
        wcsstr(lpExistingFileName, L".pptm") || wcsstr(lpExistingFileName, L".xml") ||
        wcsstr(lpExistingFileName, L".vsd") || wcsstr(lpExistingFileName, L".vsdx") ||
        wcsstr(lpExistingFileName, L".eml")) {

        auto it = accessed_filesW.find(lpExistingFileName);

        /*if (!(it != accessed_filesW.end())) {

            WCHAR pat[MAX_PATH];

            wsprintfW(pat, L"copy \"%s\" \"%sRecoverFiles\"", lpExistingFileName, tmp);
            _wsystem(pat);
            
        }*/

        accessed_filesW.insert(lpExistingFileName);

        time_t current_time = time(NULL);
        if (last_write_time == 0) last_write_time = current_time;

        if (difftime(current_time, last_write_time) > TIME_LIMIT) {
            write_count = 0;
            accessed_filesW.clear();
            last_write_time = current_time;
        }

        write_count++;

        if ((write_count >= MAX_WRITE_COUNT && accessed_filesW.size() >= MAX_WRITE_COUNT)) {
            //MessageBoxA(NULL, "SYSTEM IS INFECTED BY RANSOMWARE! PLEASE DO NOT TOUCH ANYTHING AND CALL YOUR IT NOW", "Anti-Ransomware", MB_ICONERROR | MB_OK);
            WriteSecurityBreachFile();
            TerminateProcess(OpenProcess(PROCESS_TERMINATE, FALSE, GetCurrentProcessId()), 0);
        }
    }

    BOOL res = CopyFileW(lpExistingFileName, lpNewFileName, bFailIfExists);
    InstallHook(copyFileW, &hCopyFileW, HookLib::JMP_LONG);
    return res;
}

BOOL hMoveFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName) {
    HookLib::RemoveHook(moveFileA);

    if (strstr(lpExistingFileName, ".txt") || strstr(lpExistingFileName, ".docx") ||
        strstr(lpExistingFileName, ".xlsx") || strstr(lpExistingFileName, ".pptx") ||
        strstr(lpExistingFileName, ".pdf") || strstr(lpExistingFileName, ".jpg") ||
        strstr(lpExistingFileName, ".jpeg") || strstr(lpExistingFileName, ".png") ||
        strstr(lpExistingFileName, ".gif") || strstr(lpExistingFileName, ".bmp") ||
        strstr(lpExistingFileName, ".mp3") || strstr(lpExistingFileName, ".wav") ||
        strstr(lpExistingFileName, ".zip") || strstr(lpExistingFileName, ".rar") ||
        strstr(lpExistingFileName, ".7z") || strstr(lpExistingFileName, ".tar") ||
        strstr(lpExistingFileName, ".bak") || strstr(lpExistingFileName, ".doc") ||
        strstr(lpExistingFileName, ".xls") || strstr(lpExistingFileName, ".ppt") ||
        strstr(lpExistingFileName, ".mdb") || strstr(lpExistingFileName, ".sqlite") ||
        strstr(lpExistingFileName, ".json") || strstr(lpExistingFileName, ".xml") ||
        strstr(lpExistingFileName, ".mp4") || strstr(lpExistingFileName, ".mov") ||
        strstr(lpExistingFileName, ".avi") || strstr(lpExistingFileName, ".mkv") ||
        strstr(lpExistingFileName, ".flv") || strstr(lpExistingFileName, ".wmv") ||
        strstr(lpExistingFileName, ".webm") || strstr(lpExistingFileName, ".aac") ||
        strstr(lpExistingFileName, ".ogg") || strstr(lpExistingFileName, ".m4a") ||
        strstr(lpExistingFileName, ".odt") || strstr(lpExistingFileName, ".ods") ||
        strstr(lpExistingFileName, ".odp") || strstr(lpExistingFileName, ".onetoc") ||
        strstr(lpExistingFileName, ".docm") || strstr(lpExistingFileName, ".xlsm") ||
        strstr(lpExistingFileName, ".pptm") || strstr(lpExistingFileName, ".xml") ||
        strstr(lpExistingFileName, ".vsd") || strstr(lpExistingFileName, ".vsdx") ||
        strstr(lpExistingFileName, ".eml")) {

        auto it = accessed_files.find(lpExistingFileName);
        /*
        if (!(it != accessed_files.end())) {

            CHAR pat[MAX_PATH];

            snprintf(pat, MAX_PATH, "copy \"%s\" \"%sRecoverFiles\"", lpExistingFileName, tmp);
            system(pat);

        }*/

        accessed_files.insert(lpExistingFileName);

        time_t current_time = time(NULL);
        if (last_write_time == 0) { last_write_time = current_time; }

        if (difftime(current_time, last_write_time) > TIME_LIMIT) {
            write_count = 0;
            accessed_files.clear();
            last_write_time = current_time;
        }

        write_count++;

        if ((write_count >= MAX_WRITE_COUNT && accessed_files.size() >= MAX_WRITE_COUNT)) {
            //MessageBoxA(NULL, "SYSTEM IS INFECTED BY RANSOMWARE! PLEASE DO NOT TOUCH ANYTHING AND CALL YOUR IT NOW", "Anti-Ransomware", MB_ICONERROR | MB_OK);
            WriteSecurityBreachFile();
            TerminateProcess(OpenProcess(PROCESS_TERMINATE, FALSE, GetCurrentProcessId()), 0);
        }
    }

    BOOL res = MoveFileA(lpExistingFileName, lpNewFileName);
    InstallHook(moveFileA, &hMoveFileA, HookLib::JMP_LONG);
    return res;
}

BOOL hMoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName) {
    HookLib::RemoveHook(moveFileW);

    if (wcsstr(lpExistingFileName, L".txt") || wcsstr(lpExistingFileName, L".docx") ||
        wcsstr(lpExistingFileName, L".xlsx") || wcsstr(lpExistingFileName, L".pptx") ||
        wcsstr(lpExistingFileName, L".pdf") || wcsstr(lpExistingFileName, L".jpg") ||
        wcsstr(lpExistingFileName, L".jpeg") || wcsstr(lpExistingFileName, L".png") ||
        wcsstr(lpExistingFileName, L".gif") || wcsstr(lpExistingFileName, L".bmp") ||
        wcsstr(lpExistingFileName, L".mp3") || wcsstr(lpExistingFileName, L".wav") ||
        wcsstr(lpExistingFileName, L".zip") || wcsstr(lpExistingFileName, L".rar") ||
        wcsstr(lpExistingFileName, L".7z") || wcsstr(lpExistingFileName, L".tar") ||
        wcsstr(lpExistingFileName, L".bak") || wcsstr(lpExistingFileName, L".doc") ||
        wcsstr(lpExistingFileName, L".xls") || wcsstr(lpExistingFileName, L".ppt") ||
        wcsstr(lpExistingFileName, L".mdb") || wcsstr(lpExistingFileName, L".sqlite") ||
        wcsstr(lpExistingFileName, L".json") || wcsstr(lpExistingFileName, L".xml") ||
        wcsstr(lpExistingFileName, L".mp4") || wcsstr(lpExistingFileName, L".mov") ||
        wcsstr(lpExistingFileName, L".avi") || wcsstr(lpExistingFileName, L".mkv") ||
        wcsstr(lpExistingFileName, L".flv") || wcsstr(lpExistingFileName, L".wmv") ||
        wcsstr(lpExistingFileName, L".webm") || wcsstr(lpExistingFileName, L".aac") ||
        wcsstr(lpExistingFileName, L".ogg") || wcsstr(lpExistingFileName, L".m4a") ||
        wcsstr(lpExistingFileName, L".odt") || wcsstr(lpExistingFileName, L".ods") ||
        wcsstr(lpExistingFileName, L".odp") || wcsstr(lpExistingFileName, L".onetoc") ||
        wcsstr(lpExistingFileName, L".docm") || wcsstr(lpExistingFileName, L".xlsm") ||
        wcsstr(lpExistingFileName, L".pptm") || wcsstr(lpExistingFileName, L".xml") ||
        wcsstr(lpExistingFileName, L".vsd") || wcsstr(lpExistingFileName, L".vsdx") ||
        wcsstr(lpExistingFileName, L".eml")) {

        auto it = accessed_filesW.find(lpExistingFileName);

        /*if (!(it != accessed_filesW.end())) {

            WCHAR pat[MAX_PATH];

            wsprintfW(pat, L"copy \"%s\" \"%sRecoverFiles\"", lpExistingFileName, tmp);
            _wsystem(pat);

        }*/

        accessed_filesW.insert(lpExistingFileName);

        time_t current_time = time(NULL);
        if (last_write_time == 0) { last_write_time = current_time; }

        if (difftime(current_time, last_write_time) > TIME_LIMIT) {
            write_count = 0;
            accessed_filesW.clear();
            last_write_time = current_time;
        }

        write_count++;

        if ((write_count >= MAX_WRITE_COUNT && accessed_filesW.size() >= MAX_WRITE_COUNT)) {
            //MessageBoxA(NULL, "SYSTEM IS INFECTED BY RANSOMWARE! PLEASE DO NOT TOUCH ANYTHING AND CALL YOUR IT NOW", "Anti-Ransomware", MB_ICONERROR | MB_OK);
            WriteSecurityBreachFile();
            TerminateProcess(OpenProcess(PROCESS_TERMINATE, FALSE, GetCurrentProcessId()), 0);
        }
    }

    BOOL res = MoveFileW(lpExistingFileName, lpNewFileName);
    InstallHook(moveFileW, &hMoveFileW, HookLib::JMP_LONG);
    return res;
}



namespace HookLib {

    struct HookData {
        BYTE originalBytes[20];
        void* targetFunction;
    };

    std::map<void*, HookData> hooks;

    bool InstallHook(void* targetFunction, void* hookAddress, HookType type) {
        DWORD oldProtect;
        HookData data;
        // Save the original bytes of the target function.
        memcpy(data.originalBytes, targetFunction, 20);



        data.targetFunction = targetFunction;
        hooks[targetFunction] = data;
        // Change memory protection to read/write.
        VirtualProtect(targetFunction, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        // Apply the hook based on the specified type.
        switch (type) {
        case JMP_LONG: {
            DWORD relativeAddress = ((DWORD)hookAddress - (DWORD)targetFunction) - 5;
            *(BYTE*)targetFunction = 0xE9;

#ifdef _WIN64

            * (ULONGLONG*)((ULONGLONG)targetFunction + 1) = relativeAddress;
#elif _WIN32
            * (DWORD*)((DWORD)targetFunction + 1) = relativeAddress;
#endif
            break;
        }
        default:
            break;
        }
        // Restore the original memory protection.
        VirtualProtect(targetFunction, 5, oldProtect, &oldProtect);
        return true;
    }

    bool RemoveHook(void* targetFunction) {
        auto it = hooks.find(targetFunction);
        if (it == hooks.end()) return false;

        DWORD oldProtect;
        VirtualProtect(targetFunction, 20, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(targetFunction, it->second.originalBytes, 20);
        VirtualProtect(targetFunction, 20, oldProtect, &oldProtect);

        hooks.erase(it);

        return true;
    }


}

LPVOID loadFunc(LPCSTR dll, LPCSTR func) {
    LPVOID targetFunc = (LPVOID)GetProcAddress(GetModuleHandleA(dll), func);

    if (!targetFunc) {
        MessageBoxA(NULL, "Failed to locate the function", "ERROR", MB_OK);
        ExitThread(0);
    }
    return targetFunc;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        /*DisableThreadLibraryCalls(hModule);
        g_hToken = GetProcessToken();
        if (g_hToken) {
            g_hMonitorThread = CreateThread(NULL, 0, TokenMonitorThread, NULL, 0, NULL);
        }*/


        GetTempPathA(MAX_PATH, tmp);
        
        //wf = loadFunc("kernel32.dll", "WriteFile");
        //InstallHook(wf, &hWriteFile, HookLib::JMP_LONG);

        nwf = loadFunc("ntdll.dll", "NtWriteFile");
        InstallHook(nwf, &hNtWriteFile, HookLib::JMP_LONG);

        moveFileA = loadFunc("kernel32.dll", "MoveFileA");
        InstallHook(moveFileA, &hMoveFileA, HookLib::JMP_LONG);
        moveFileW = loadFunc("kernel32.dll", "MoveFileW");
        InstallHook(moveFileW, &hMoveFileW, HookLib::JMP_LONG);

        copyFileA = loadFunc("kernel32.dll", "CopyFileA");
        InstallHook(copyFileA, &hCopyFileA, HookLib::JMP_LONG);
        copyFileW = loadFunc("kernel32.dll", "CopyFileW");
        InstallHook(copyFileW, &hCopyFileW, HookLib::JMP_LONG);
        
        break;
    }
    return TRUE;
}