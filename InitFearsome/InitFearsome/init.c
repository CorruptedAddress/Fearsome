#include <Windows.h>
#include <stdio.h>
#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

TCHAR* GetThisPath(TCHAR* dest, size_t destSize)
{
    if (!dest) return NULL;
    if (MAX_PATH > destSize) return NULL;

    DWORD length = GetModuleFileName(NULL, dest, destSize);
    PathRemoveFileSpec(dest);
    return dest;
}

void main() {
    TCHAR dest[MAX_PATH];
    GetThisPath(dest, MAX_PATH);
    TCHAR c1[MAX_PATH], c2[MAX_PATH], c3[MAX_PATH];
    //printf("Path: %ls\n", dest);
    snprintf(c1, MAX_PATH, "start /D \"%ls\" x64\\DllInjector.exe x64\\Hook.dll", dest, dest);
    snprintf(c2, MAX_PATH, "start /D \"%ls\" x86\\DllInjector.exe x86\\Hook.dll", dest, dest);
    //printf("%s\n", c1);
    //printf("%s\n", c2);
    CHAR tmp[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    printf("%s\n",tmp);
    snprintf(c3, MAX_PATH, "mkdir %sRecoverFiles", tmp);
    system(c3);

	system(c1);
	system(c2);
}