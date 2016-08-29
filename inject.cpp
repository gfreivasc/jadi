#include <cstdio>
#include <Windows.h>

int main(int argc, char *argv[]) {
    char appName[_MAX_PATH];
    char dllName[_MAX_PATH];

    // Get app and dll name from 
    if (argc < 2) {
        strcpy(appName, "helloworld.exe");
    } 
    else {
        strcpy(appName, argv[1]);
    }

    if (argc < 3) {
        strcpy(dllName, "hook.dll");
    }
    else {
        strcpy(dllName, argv[2]);
    }

    // We need to capture process information once we create it
    // To create process, we need to supply some startup info..
    // This is generic, see MSDN for more information
    // https://msdn.microsoft.com/en-us/library/ms682425.aspx
    PROCESS_INFORMATION piProcInfo;
    STARTUPINFO         siStartupInfo;

    memset(&piProcInfo, 0, sizeof(piProcInfo));
    memset(&siStartupInfo, 0, sizeof(siStartupInfo));

    siStartupInfo.cb = sizeof(siStartupInfo);
    siStartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    siStartupInfo.wShowWindow = SW_HIDE;

    if(!CreateProcessA(appName, NULL, NULL, NULL, FALSE, NULL,
        NULL, NULL, &siStartupInfo, &piProcInfo)) {
        printf("[ERROR] Cannot open process %s\n", appName);
        return 0;
    }
    
    // Process started, throw our dll in
    // First, capture LoadLibraryA from kernel32.dll
    HMODULE hKernel32;
    LPVOID  lpLoadLibraryA;
    
    hKernel32 = GetModuleHandle("kernel32.dll");
    lpLoadLibraryA = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");

    // Then we need to allocate memory in the process for our .dll name
    // This needs to be done because our remote thread will read the
    // remote process memory once it's there, not current dll memory
    LPVOID lpMemory;
    lpMemory = (LPVOID)VirtualAllocEx(piProcInfo.hProcess, NULL,
        sizeof(dllName), MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(piProcInfo.hProcess, lpMemory, (LPVOID)dllName,
        sizeof(dllName), NULL);

    // Now the memory is set up and we have LoadLibraryA, we simply
    // need to create a remote thread that will run LoadLibraryA with
    // our dll in the remote process
    HANDLE hThread;
    hThread = CreateRemoteThread(piProcInfo.hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)lpLoadLibraryA, lpMemory, 0, NULL);

    if (!hThread) {
        printf("[ERROR] Couldn't open LoadLibraryA thread. Dll not injected.\n");
        return 0;
    }

    // Our thread is running, wait for it to return. If thread executed fine,
    // it will return WAIT_OBJECT_0, that is, our thread returned 0 (OK)
    // WAIT_OBJECT_0 == 0x00000000L
    if(WaitForSingleObject(hThread, INFINITE)) {
        printf("[ERROR] Thread didn't return 0. Dll not injected.\n");
        return 0;
    }

    // However, this doesn't mean our .dll was injected. To be sure,
    // We need to check thread exit status code, that is, in this case,
    // LoadLibraryA return value. Also check if get exit code succeeds
    DWORD hDll;
    if (!GetExitCodeThread(hThread, &hDll)) {
        printf("[ERROR] Can't get LoadLibraryA return handle.\n");
        return 0;
    }

    if (hDll == 0x00000000) {
        printf("[ERROR] LoadLibraryA couldn't inject dll.\n");
        return 0;
    }

    // Let the process return it's intended course. Clean up
    CloseHandle(hThread);
    VirtualFreeEx(piProcInfo.hProcess, lpMemory, sizeof(dllName), MEM_RELEASE);
    CloseHandle(piProcInfo.hThread);
    CloseHandle(piProcInfo.hProcess);
    return 0;
}