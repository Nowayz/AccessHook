#pragma once
//========= Property of 3rdEra, All rights reserved. ============//
// Contributers: Phillip McNallen
//         Name: AccessHook.h
//         Desc: Hook functions in an x86 process address space without modifying memory
//=============================================================================//

// Call original_function while bypassing its hook to prevent infinite re-entry
#define HOOK_BYPASS(original_function, ...)  (AccessHookSkipNext(original_function), original_function(__VA_ARGS__))

void AccessHookSkipNext(void* original_function_address);
void AccessHookAdd(void* original_function_address, void* new_function_address);
void AccessHookRemove(void* original_function_address);