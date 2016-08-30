# just another dll injector

jadi is just another tutorial for a C++ dll injector.
jadi is not meant to be a top class dll injector.
Instead, the goal here is to introduce people to how a dll injector works.
It uses a basic approach and definitely is _NOT_ intended to be used where it shouldn't be
(Don't try to inject a hack dll with it as proper bypass is not covered here).
The full code is available in this repository.

## Introduction
Before we get started we need to understand what is to be done here.
Dll injection is not so simple and requires not only programming knowledge,
but basic (at least) notions of how operational systems work.
Here we need to understand what means to say process memory, what are threads, hadling a process, etc.
If you intend to dive deeper into reverse engineering topics, you'll need to keep studying operational systems simultaneously.
This is not beginner stuff, but I'll make it as simple as I can.

## Contents
- Starting our code
    - Our includes
    - Program skeleton
- Creating remote process
    - Needed info
    - The handles
- Getting the guy that will load our .dll
    - What is LoadLibraryA
    - What is a long pointer?
    - Getting LoadLibraryA from remote module
- Write our .dll path to remote process memory
    - Why write it to remote process?
    - Write the memory, save it's address
- Create the .dll loading thread 
    - How remote thread works
    - Have we succeeded?
- Clearing up
- Next steps
- Credits

## Starting our code
Here we will use C++. Like it or hate it, it is by far the most apropriated language (along with it's father C) for reverse engineering yet these days.
It can handle close to low level and even low level instructions and statements, and still is reasonably easy to understand.
Not as abstract as Python, C++ still let's you make a lot of stuff without having to deal directly with concepts such as segmentation and hardware interrupts.

### Our includes
Let's not get offtopic, for this guy to work we will need to include `cstdio` (aka `stdio.h`) to pop messages in case something goes wrong.
Also, we will be dealing with many operational system subroutines here, so we need to include Windows default library `Windows.h`.

### Program skeleton 
To make jadi's runtime somewhat tweakable, we can allow user to input the executable and the dll path through `argv` (necessarily in that order).
Of course we will have default values. Lets say we wan't to inject a dll that hooks a helloworld program and call our target application
`helloworld.exe` and our dll is `hook.dll`.

```c++
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

    // The injection stuff will happen here

    return 0;
}
```
We use `_MAX_PATH` here because it is better to use Windows default than something hardcoded by ourselves. The value is currently 256.

## Creating remote process
Now that we have our target path, we have all we need to open it... Right? Unfortunatelly, no. Atleast, not the way we have to.
To be able to work over our process after we create it, we'll need to save one particular value. That is our process handle. We'll see it soon.

### Needed info
We will call Windows function CreateProcessA function (that is, the ASCII version of [`CreateProcess`](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx))).
It takes a shitload of info, most we don't need to care about. The first parameter is `lpApplicationName`, that is, `appName`.
The bad guy here is `lpStartupInfo`. This is info we need to feed although we don't care about. Ignore this and things will misbehave (or crash).
For that, we simply copy and paste some default stuff;

```c++
STARTUPINFO         siStartupInfo;

memset(&siStartupInfo, 0, sizeof(siStartupInfo));

siStartupInfo.cb = sizeof(siStartupInfo);
siStartupInfo.dwFlags = STARTF_USESHOWWINDOW;
siStartupInfo.wShowWindow = SW_HIDE;
```
We set stuff to 0 because we declared `siStartupInfo` inside `main()`, and it is likely filled with garbage. Clear it up and fill proper data
The following item is what we want (maybe purposely placed as last parameter, so people read the other stuff). That is `lpProcessInformation`.
We will pass this pointer to the function, and once the process has been created, we will have some interesting data.
Now after parsing values for dll and app names we have

```c++
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
```
I added some checks just to be sure. If `CreateProcessA` fails, it returns `false`.

### The handles
What makes our variable `piProcInfo` so interesting is that it contains handles. More specifically, it has our remote process (target application) handle.
See the declaration of the [`PROCESS_INFORMATION`](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx) struct for more intel.
But, you might be asking, what is a handle? Long story short, a handle is a value that Windows provides that allows a process to manipulate a remote process.
As long as the Handle is open, you can manage a remote process through various subroutins. Hacky, isn't it?
The `hThread` handle provided allows you to manipulate exclusively the process primary thread. That's not the one we're aiming at here.
The `hProcess` handle is our guy, and it will allow us to perform our dll injection.

## Getting the guy that will load our .dll
Now that we've created a process and have hands on it's handle, we're one step closer to getting our dll insite it.
But, unfortunatelly, among the many possibilities provided by the handle, directly loading a dll isn't one. We need to hack things a bit here.

### What is LoadLibraryA
Windows has a function for that, it is `LoadLibraryA` (Just like `CreateProcessA`, its an ASCII version for [`LoadLibrary`](https://msdn.microsoft.com/pt-br/library/windows/desktop/ms684175(v=vs.85).aspx)).
The only parameter that it takes is the dll path. In our case, it is simply `dllName`.
But, as I said, there is no direct way to load our dll. It means we can't simply call `LoadLibraryA` and things will work.
What we have to do here is a trick to call `LoadLibraryA` from inside the remote process.
Things don't stop there, we can't simply use the `LoadLibraryA` included through `Windows.h`.
We will have to call it straight from where it is originally, `kernel32.dll`.
It happens because windows allocate memory differently between x86 and x64 processes,
and the only way to prevent calling something different is stripping it straight from its source. And saving it to a pointer. A long pointer.

### What is a long pointer?
It's not a pointer meant for a big clock (it might be, but not in our case).
A long pointer (or far pointer) has a wider range than a normal pointer, or short pointer.
Not every processor has this treatment, but as some have, it's cautious to follow the protocol.
We will have to keep the address of a function in an external library inside jadi, that means we'll have to jump at least the range of a whole process to reach our pointer.
That this takes a wide range is common sense, so it's logical to use long pointer here. 
Therefore we'll use a long void pointer instead of a common one. Windows has a typedef for it, that is `LPVOID` (Seeing type definitions for CreateProcess will tell us that this is not the first time this pops up here).

### Getting LoadLibraryA from remote module
Now that we know more or less what to do, let's get to work. First thing we have to do is get `kernel32.dll` module handle.
Since it's defaultly imported by every windows process heard about, we can get it through [`GetModuleHandle`](https://msdn.microsoft.com/pt-br/library/windows/desktop/ms683199(v=vs.85).aspx).
Once we have this handle, we need to find `LoadLibraryA` symbol address in there.
[`GetProcAddress`](https://msdn.microsoft.com/pt-br/library/windows/desktop/ms683212(v=vs.85).aspx) will do the trick.
Our code for getting `LoadLibraryA` is as follows

```c++
HMODULE hKernel32;
LPVOID  lpLoadLibraryA;
    
hKernel32 = GetModuleHandle("kernel32.dll");
lpLoadLibraryA = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
```
And we have a function to call inside our target.

## Write our .dll path to remote process memory
But before calling the LoarLibrary routine, we need to write our parameter inside remote process' memory.

### Why write it to remote process?
Yet another hacky trick, the target application cannot read jadi's internal data. And dllName is there.
So we will have to place dllName somewhere the remote process can read. That is, of course, it's own memory.

### Write the memory, save it's address
Thanks to our holy handle, we can do it! First we need to save space in our target memory to place our data. We'll need to allocate a range in process memory and save it's address. This address will have to be placed in an specific kind of pointer given that it lies in a different application. If you guessed we'd use long pointers, you were right!
To reserve our spot in the remote process' memory, [`VirtualAllocEx`](https://msdn.microsoft.com/pt-br/library/windows/desktop/aa366890(v=vs.85).aspx) is what we need.
After we have this space allocated, we write to it (once again, through the handle, it's not our memory).
Instead of a simple `strcpy`, we'll have to ask almighty [`WriteProcessMemory`](https://msdn.microsoft.com/pt-br/library/windows/desktop/ms681674(v=vs.85).aspx) for help.
Finally, we have:

```c++
LPVOID lpMemory;
lpMemory = (LPVOID)VirtualAllocEx(piProcInfo.hProcess, NULL,
    sizeof(dllName), MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(piProcInfo.hProcess, lpMemory, (LPVOID)dllName,
    sizeof(dllName), NULL);
```

## Create the .dll loading thread
Now we're fully set up for injecting our dll. We will open a concurrent thread that will call `LoadLibraryA` for us with our defined memory.
Via handle, we can call [`CreateRemoteThread`](https://msdn.microsoft.com/pt-br/library/windows/desktop/ms682437(v=vs.85).aspx) to place our thread.

```c++
HANDLE hThread;
hThread = CreateRemoteThread(piProcInfo.hProcess, NULL, 0,
    (LPTHREAD_START_ROUTINE)lpLoadLibraryA, lpMemory, 0, NULL);

if (!hThread) {
    printf("[ERROR] Couldn't open LoadLibraryA thread. Dll not injected.\n");
    return 0;
}
```
Voilà! Our dll has been injected! But wait a minute! Has it really?

### How remote thread works
If you've studied concurency before, you know that creating a thread is not the whole thing.
It has to stop at some point, preferably before main thread stops.
Usually threads are created and expected to finish at a given point, where the program synchronizes and continues.
It's not a general case, but it is our case. There are some routines to work with remote threads, but here we only care about two things.
Wait until it finishes. Then get it's exit code. The way we've dealt with it only tells us wether it has been opened or not. 
We can't tell if it is looping there, if it has crashed, or if `LoadLibraryA` failed. That's why we need these two things.

### Have we succeeded?
To proceed to our next checks, we'll need two functions:
- [`WaitForSingleObject`](https://msdn.microsoft.com/pt-br/library/windows/desktop/ms687032(v=vs.85).aspx) can be called, will only return when thread closes, preventing busy waiting.
- [`GetExitCodeThread`](https://msdn.microsoft.com/pt-br/library/windows/desktop/ms683190(v=vs.85).aspx) will get thread exit code. Here, `LoadLibraryA` return value.
If you are a good kid, you've read the `LoadLibrary` documentation and know that it returns dll's base address if it succeeds, or NULL if it doesn't.
Therefore, we now have to check if `WaitForSingleObject` returns with an OK status (`0x00000000`), and if `GetExitCodeThread` returns with a reasonable base address (not `0x00000000`).

```c++
if(WaitForSingleObject(hThread, INFINITE)) {
    printf("[ERROR] Thread didn't return 0. Dll not injected.\n");
    return 0;
}

DWORD hDll;
if (!GetExitCodeThread(hThread, &hDll)) {
    printf("[ERROR] Can't get LoadLibraryA return handle.\n");
    return 0;
}

if (hDll == 0x00000000) {
    printf("[ERROR] LoadLibraryA couldn't inject dll.\n");
    return 0;
}
```

If all goes fine, the dll has successfully been injected.

## Clearing up
Now that we have things up and running, we need to take cautious matters. We don't need the handles anymore, we can close them.
Also, we have allocated space in the process memory, but it can't control it as it wasn't coded for that. We have to free it ourselves.

```c++
CloseHandle(hThread);
VirtualFreeEx(piProcInfo.hProcess, lpMemory, sizeof(dllName), MEM_RELEASE);
CloseHandle(piProcInfo.hThread);
CloseHandle(piProcInfo.hProcess);
```
And that's it, jadi is fully operational!

## Next steps
Now that you've reached the end of this tutorial, you can advance in your studies of the Windows library in MSDN.
If you will, you can refine it by freeing the dll after it's injected and executed (hint: DllMain will return then).
Also, perhaps, make it stealth? So much for us to learn!

## Credits
Credits for Gabriel Vasconcelos, [Code Project](http://www.codeproject.com/) for it's snippets and the great
DLL Injection article in [Wikipedia](https://en.wikipedia.org/wiki/DLL_injection). And of course, the main knowledge base of all of this,
[MSDN](https://msdn.microsoft.com/).
