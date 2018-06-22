# AccessHook
AccessHook is a process hacking library, written in C, for 64-bit Windows.

Functions can be hooked by calling **`AccessHookAdd`**, and unhooked by calling **`AccessHookRemove`**.

Using the macro **`HOOK_BYPASS`** allows calling the original function while skipping the hook.  Use this when calling the original function inside of a hook function.

## Example Usage:

```cpp
#include <Windows.h>
#include "AccessHook.h"

int WINAPI HookMessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	HOOK_BYPASS(MessageBoxA, hWnd, "Injected MessageBox, created using AccessHook.", lpCaption, uType);
	return HOOK_BYPASS(MessageBoxA, hWnd, lpText, lpCaption, uType);
}

int main(int argc, char* argv[]) 
{
	AccessHookAdd(MessageBoxA, HookMessageBoxA);
	MessageBoxA(0, "This is a default success message.", "AccessHook Example", MB_OKCANCEL);
	
	AccessHookRemove(MessageBoxA);
	MessageBoxA(0, "This message should appear with no hook!.", "AccessHook Example", MB_OKCANCEL);
	
	return 0;
}
```

## Remarks
__AccessHook does not modify bytecode inside of a process__, and can hook function calls without failing code integrity checks. 

The only caveat, currently, is that the memory protection flags of hooked pages will be clearly marked as **`PAGE_READONLY`** rather than their intended values.  Some software only validates its own module's bytecode in the memory and not **ntdll.dll**; meaning the page protection can be disguised by merely hooking **`NtQueryVirtualMemory`**(not using AccessHook), and modifying its return.

Hooking **`NtQueryVirtualMemory`** with AccessHook is impossible because the exception dispatcher calls this function while dispatching the exception and will create an infinite loop until a stack overflow occurs.

If this approach is taken, make sure to hook all three types of calls: `MemoryBasicInformation` `MemoryWorkingSetList`, and `MemoryWorkingSetExList`.