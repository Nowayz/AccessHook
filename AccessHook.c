//========= Property of 3rdEra, All rights reserved. ============//
// Contributers: Phillip McNallen
//         Name: AccessHook.h
//         Desc: Hook functions in an x86 process address space without modifying memory
//
//                                           ** This is NOT THREAD SAFE! ** 
//   ** If hooks NEED to operate on multiple threads while records are being added or removed, atomic operations MUST be added! **
//=============================================================================//
#include "AccessHook.h"
#include <Windows.h>
#include <stdint.h>

////////////////////
// CPU FLAGS
///////
#define EFLAGS_TRACE 0x100
#define DEBUGCTL_BTF 0b10  
#define DEBUGCTL_LBR 0b1
#define DR7_BTF 0b1000000000
#define DR7_LBR 0b100000000


////////////////////
// MISCELLANEOUS
///////
#define MAX_HOOKS 24
#define ARRAY_SIZE(array) (sizeof((array))/sizeof((array[0])))
const HMODULE NTBASE = HMODULE(*(**(*(uintptr_t****)(__readgsqword(0x60) + 0x18) + 0x4) + 0x4));       // Base address of ntdll.dll
const HMODULE KERNELBASE = HMODULE(*(***(*(uintptr_t*****)(__readgsqword(0x60) + 0x18) + 0x4) + 0x4)); // Base address of kernel32.dll


////////////////////
// UTILITY FUNCTIONS
///////
inline void* GetPageBase(void* addr)
{
    size_t tmp = (size_t)addr;
    return (void*)(tmp&~4095);
}


////////////////////
// NTAPI DEFINITIONS
///////
typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,
    MemoryWorkingSetList,
    MemorySectionName,
    MemoryBasicVlmInformation,
    MemoryWorkingSetExList
} MEMORY_INFORMATION_CLASS;

NTSTATUS(_stdcall*NtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) = (NTSTATUS(_stdcall*)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection))(void*)GetProcAddress(NTBASE, "NtProtectVirtualMemory");
NTSTATUS(_stdcall*NtQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID Buffer, SIZE_T Length, PSIZE_T ResultLength) = (NTSTATUS(_stdcall*)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID Buffer, SIZE_T Length, PSIZE_T ResultLength))(void*)GetProcAddress(NTBASE, "NtQueryVirtualMemory");


////////////////////
// INTERNAL HOOK RECORDS
///////
void* ActiveHookPages[MAX_HOOKS]           = { 0 };  // Pointer array of memory page addresses containing hooked functions.
void* OriginalFunctionAddresses[MAX_HOOKS] = { 0 };  // Pointer array of start addresses of all hooked functions.
void* NewFunctionAddresses[MAX_HOOKS]      = { 0 };  // Pointer array of new functions which will be called for each corresponding function in 'OriginalFunctionAddresses'.
int   SkipNextHook[MAX_HOOKS]              = { 0 };  // Boolean array indicating whether to skip hook redirection, allowing the original function to execute instead.
DWORD CorrectProtection[MAX_HOOKS]         = { 0 };  // Array of correct page protections.  Required to spoof expected protection flags.


// NtProtectPage
//     Modify memory protection for a single page in virtual memory
//
//                BaseAddress =  Pointer to a memory location representing the page in which it resides.
//        NewAccessProtection =  Memory protection constant value: https://msdn.microsoft.com/en-us/library/windows/desktop/aa366786(v=vs.85).aspx
NTSTATUS NtProtectPage(void* BaseAddress, ULONG NewAccessProtection) {
    SIZE_T numBytes  = 1;
    DWORD  oldAccess = NULL;
    PVOID  baseAddr  = BaseAddress;
    return NtProtectVirtualMemory(HANDLE(-1), &baseAddr, &numBytes, NewAccessProtection, &oldAccess);
}


// GetHookFunction
//     Returns pointer address of hook function for "addr";
//     if no function pointer is found for "addr", returns NULL.
//
//        addr  =  Pointer to instruction being checked for a hook function.
void* GetHookFunction(void* addr) {
    for (int i = 0; i < ARRAY_SIZE(OriginalFunctionAddresses); i++) {
        if (OriginalFunctionAddresses[i] == addr) {
            return NewFunctionAddresses[i];
        }
    }
    return NULL;
}


// IsHookedPage
//     Returns 1(TRUE) if the specified page contains a hooked function,
//     otherwise returns 0(FALSE).
//
//        base_page_address  =  Pointer to the base address of a memory page.
int IsHookedPage(void* base_page_address) {
    for (int i = 0; i < ARRAY_SIZE(ActiveHookPages); i++) {
        if (ActiveHookPages[i] == base_page_address) {
            return true;
        }
    }
    return false;
}


void AddHookedPageBase(void* base_page_address) {
    for (int i = 0; i < ARRAY_SIZE(ActiveHookPages); i++) {
        if (ActiveHookPages[i] == NULL) {
            // Request and store original page protection value
            MEMORY_BASIC_INFORMATION mbi = { 0 };
            NtQueryVirtualMemory(HANDLE(-1), base_page_address, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
            CorrectProtection[i] = mbi.Protect;

            // Add address to active pages
            ActiveHookPages[i] = base_page_address;
            break;
        }
    }
}


void RemoveHookedPageBase(void* base_page_address) {
    for (int i = 0; i < ARRAY_SIZE(ActiveHookPages); i++) {
        if (ActiveHookPages[i] == base_page_address) {
            // Reset page protection to original value
            NtProtectPage(base_page_address, CorrectProtection[i]);

            // Clear page from active pages list
            ActiveHookPages[i] = NULL;
        }
    }
}


void AddHookedAddress(void* original_function_address, void* new_function_address) {
    for (int i = 0; i < ARRAY_SIZE(OriginalFunctionAddresses); i++) {
        if (OriginalFunctionAddresses[i] == NULL) {
            OriginalFunctionAddresses[i] = original_function_address;
            NewFunctionAddresses[i]      = new_function_address;
            SkipNextHook[i]              = FALSE;
            break;
        }
    }
}


void RemoveHookedAddress(void* original_function_address) {
    for (int i = 0; i < ARRAY_SIZE(OriginalFunctionAddresses); i++) {
        if (OriginalFunctionAddresses[i] == original_function_address) {
            OriginalFunctionAddresses[i] = NULL;
            NewFunctionAddresses[i]      = NULL;
        }
    }
}


void AccessHookSkipNext(void* original_function_address) {
    for (int i = 0; i < ARRAY_SIZE(OriginalFunctionAddresses); i++) {
        if (OriginalFunctionAddresses[i] == original_function_address) {
            SkipNextHook[i] = TRUE;
        }
    }
}


int ShouldSkipHook(void* original_function_address) {
    for (int i = 0; i < ARRAY_SIZE(OriginalFunctionAddresses); i++) {
        if (OriginalFunctionAddresses[i] == original_function_address) {
            if (SkipNextHook[i]) {
                SkipNextHook[i] = FALSE; // reset on skip
                return TRUE;
            }
            else {
                return FALSE;
            }
        }
    }
    return FALSE; // unreachable
}


// ExceptionFilter
//     Handles exceptions thrown by all threads; any related to 
//     AccessHook are handled and hook functions are called.
//  
//       pExceptionInfo  =  Exception records provided by the Vectored Exception Handler
LONG WINAPI ExceptionFilter(EXCEPTION_POINTERS* pExceptionInfo)
{
    DWORD dwtmp;
    /*thread_local*/ static void* lastExceptionAddress = NULL;
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) { // Entering hook page
        void* ripRegionBase = GetPageBase((void*)pExceptionInfo->ContextRecord->Rip);
        void* lastExceptionRegionBase = GetPageBase(lastExceptionAddress);
        if (IsHookedPage(ripRegionBase)) {
            lastExceptionAddress = (void*)pExceptionInfo->ContextRecord->Rip;
            void* hookFunc       = GetHookFunction((void*)pExceptionInfo->ContextRecord->Rip);
            if (hookFunc) { // Currently on hooked address
                if (!ShouldSkipHook((void*)pExceptionInfo->ContextRecord->Rip)) {
                    pExceptionInfo->ContextRecord->Rip = (DWORD64)hookFunc;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
            NtProtectPage(ripRegionBase, PAGE_EXECUTE_READ);

            pExceptionInfo->ContextRecord->EFlags       |= EFLAGS_TRACE;
            pExceptionInfo->ContextRecord->Dr7          |= DR7_BTF;      // Faster stepping  (not required to operate)
            pExceptionInfo->ContextRecord->DebugControl |= DEBUGCTL_BTF; // Faster stepping  (not required to operate)

            if (ripRegionBase != lastExceptionRegionBase) { // Exited old hook page into another hook page
                NtProtectPage(lastExceptionRegionBase, PAGE_READONLY);
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    } 
    else if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) { // Step through page, and handle exit from page
        void* ripRegionBase           = GetPageBase((void*)pExceptionInfo->ContextRecord->Rip);
        void* lastExceptionRegionBase = GetPageBase(lastExceptionAddress);
        if (IsHookedPage(ripRegionBase) || IsHookedPage(lastExceptionRegionBase)) {
            if (ripRegionBase != lastExceptionRegionBase) { // Exiting hook page (occurs upon entry of another page); set memory access trap
                NtProtectPage(lastExceptionRegionBase, PAGE_READONLY);
                pExceptionInfo->ContextRecord->EFlags &= ~EFLAGS_TRACE;
            }
            else { // Trapped and in hook page, continue stepping
                lastExceptionAddress = (void*)pExceptionInfo->ContextRecord->Rip;
                pExceptionInfo->ContextRecord->EFlags |= EFLAGS_TRACE;
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void AccessHookAdd(void* original_function_address, void* new_function_address)
{
    static int firstRun = 1;
    if (firstRun--) {
        AddVectoredExceptionHandler(true, ExceptionFilter);
    }

    void* hookRegionBase = GetPageBase(original_function_address);
    if (!IsHookedPage(hookRegionBase)) {
        AddHookedPageBase(hookRegionBase);
    }
    AddHookedAddress(original_function_address, new_function_address);

    // Set PAGE_READONLY to begin trapping execution for our hook
    NtProtectPage(hookRegionBase, PAGE_READONLY);
}


void AccessHookRemove(void* original_function_address)
{
    RemoveHookedAddress(original_function_address);
    void* hookRegionBase = GetPageBase(original_function_address);
    for (int i = 0; i < ARRAY_SIZE(OriginalFunctionAddresses); i++) {
        if (GetPageBase(OriginalFunctionAddresses[i]) == hookRegionBase)
            goto skip_page_unhook;
    }
    RemoveHookedPageBase(hookRegionBase);
skip_page_unhook:;
}