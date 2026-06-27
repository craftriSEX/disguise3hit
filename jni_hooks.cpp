#include "jni_hooks.h"
#include <windows.h>
#include <cstdio>
#include <cstdarg>
#include <string>
#include <vector>
#include <thread>
#include <chrono>

namespace jni {

static JNIEnv* g_env = nullptr;
static CRITICAL_SECTION g_logCs;
static bool g_logInit = false;

void InitLog() {
    if (!g_logInit) { InitializeCriticalSection(&g_logCs); g_logInit = true; }
}

void WriteLog(const char* fmt, ...) {
    InitLog();
    EnterCriticalSection(&g_logCs);
    FILE* f = fopen("C:\\craftrise\\log.txt", "a");
    if (f) {
        fprintf(f, "[@minhook.h] ");
        va_list ap; va_start(ap, fmt);
        vfprintf(f, fmt, ap); va_end(ap);
        fprintf(f, "\n"); fclose(f);
    }
    LeaveCriticalSection(&g_logCs);
}

static HANDLE g_hitEvent = nullptr;
static uintptr_t g_targetAddr = 0;
static uint8_t g_savedByte = 0;
static volatile bool g_done = false;
static void (*g_callback)(JNIEnv*) = nullptr;

static LONG WINAPI VehCb(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;
    if ((uintptr_t)ep->ExceptionRecord->ExceptionAddress != g_targetAddr) return EXCEPTION_CONTINUE_SEARCH;
    if (g_done) return EXCEPTION_CONTINUE_SEARCH;

    JNIEnv* env = (JNIEnv*)ep->ContextRecord->Rcx;
    if (!env) return EXCEPTION_CONTINUE_SEARCH;

    g_env = env;
    g_done = true;
    WriteLog("JNIEnv captured: %p TID=%lu", (void*)env, GetCurrentThreadId());

    DWORD old;
    VirtualProtect((LPVOID)g_targetAddr, 1, PAGE_EXECUTE_READWRITE, &old);
    *(uint8_t*)g_targetAddr = g_savedByte;
    VirtualProtect((LPVOID)g_targetAddr, 1, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (LPCVOID)g_targetAddr, 1);

    if (g_callback) g_callback(env);
    ep->ContextRecord->Rip = g_targetAddr;
    if (g_hitEvent) SetEvent(g_hitEvent);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static bool TryTarget(const char* label, uintptr_t addr, int timeout_ms) {
    if (!addr) return false;
    g_targetAddr = addr;
    g_done = false;
    g_hitEvent = CreateEventA(nullptr, FALSE, FALSE, nullptr);
    AddVectoredExceptionHandler(1, VehCb);

    g_savedByte = *(uint8_t*)addr;
    DWORD old;
    VirtualProtect((LPVOID)addr, 1, PAGE_EXECUTE_READWRITE, &old);
    *(uint8_t*)addr = 0xCC;
    VirtualProtect((LPVOID)addr, 1, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (LPCVOID)addr, 1);

    WriteLog("INT3 on %s (%p) wait %dms", label, (void*)addr, timeout_ms);
    DWORD wait = WaitForSingleObject(g_hitEvent, timeout_ms);
    RemoveVectoredExceptionHandler(VehCb);
    if (g_hitEvent) { CloseHandle(g_hitEvent); g_hitEvent = nullptr; }

    if (wait != WAIT_OBJECT_0) {
        VirtualProtect((LPVOID)addr, 1, PAGE_EXECUTE_READWRITE, &old);
        *(uint8_t*)addr = g_savedByte;
        VirtualProtect((LPVOID)addr, 1, old, &old);
        FlushInstructionCache(GetCurrentProcess(), (LPCVOID)addr, 1);
        g_targetAddr = 0;
        WriteLog("INT3 on %s timed out", label);
        return false;
    }
    return true;
}

bool CaptureClientThreadEnv(void (*cb)(JNIEnv*)) {
    InitLog();
    g_callback = cb;
    g_env = nullptr;

    HMODULE jvm = GetModuleHandleA("jvm.dll");
    HMODULE lwjgl = GetModuleHandleA("lwjgl64.dll");
    if (!lwjgl) lwjgl = GetModuleHandleA("lwjgl.dll");

    if (jvm) {
        uintptr_t nano = (uintptr_t)GetProcAddress(jvm, "JVM_NanoTime");
        if (nano) {
            WriteLog("trying JVM_NanoTime");
            if (TryTarget("JVM_NanoTime", nano, 15000)) return true;
        }
    }

    if (jvm) {
        uintptr_t ctm = (uintptr_t)GetProcAddress(jvm, "JVM_CurrentTimeMillis");
        if (ctm) {
            WriteLog("trying JVM_CurrentTimeMillis");
            if (TryTarget("JVM_CurrentTimeMillis", ctm, 10000)) return true;
        }
    }

    if (lwjgl) {
        auto dos = (IMAGE_DOS_HEADER*)lwjgl;
        auto nt = (IMAGE_NT_HEADERS*)((uint8_t*)lwjgl + dos->e_lfanew);
        auto ed = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        std::vector<std::pair<std::string, uintptr_t>> ex;
        if (ed->Size) {
            auto exp = (IMAGE_EXPORT_DIRECTORY*)((uint8_t*)lwjgl + ed->VirtualAddress);
            auto n = (uint32_t*)((uint8_t*)lwjgl + exp->AddressOfNames);
            auto f = (uint32_t*)((uint8_t*)lwjgl + exp->AddressOfFunctions);
            auto o = (uint16_t*)((uint8_t*)lwjgl + exp->AddressOfNameOrdinals);
            for (DWORD i = 0; i < exp->NumberOfNames; i++)
                ex.push_back({(const char*)((uint8_t*)lwjgl + n[i]), (uintptr_t)lwjgl + f[o[i]]});
        }
        WriteLog("LWJGL at %p %zu exports", (void*)lwjgl, ex.size());
        for (auto& e : ex) {
            if (e.first.find("Java_") != std::string::npos && e.first.find("Display") != std::string::npos) {
                WriteLog("trying %s", e.first.c_str());
                if (TryTarget(e.first.c_str(), e.second, 10000)) return true;
                break;
            }
        }
        for (auto& e : ex) {
            if (e.first.find("Java_") != std::string::npos) {
                WriteLog("trying %s", e.first.c_str());
                if (TryTarget(e.first.c_str(), e.second, 10000)) return true;
                break;
            }
        }
    }

    WriteLog("all targets failed");
    return false;
}

void Cleanup() {
    if (g_targetAddr && g_savedByte) {
        DWORD old;
        VirtualProtect((LPVOID)g_targetAddr, 1, PAGE_EXECUTE_READWRITE, &old);
        *(uint8_t*)g_targetAddr = g_savedByte;
        VirtualProtect((LPVOID)g_targetAddr, 1, old, &old);
    }
    g_env = nullptr; g_targetAddr = 0; g_done = false;
}

JNIEnv* GetEnv() { return g_env; }

}
