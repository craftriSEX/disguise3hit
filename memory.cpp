#include "memory.h"

namespace memory {

static uintptr_t AllocNear(uintptr_t target, size_t size) {
    MEMORY_BASIC_INFORMATION mbi;
    for (uintptr_t base = target & ~0xFFFFull;
         base > (target & ~0xFFFFull) - 0x7FFFFFFFull; base -= 0x10000) {
        if (VirtualQuery((LPCVOID)base, &mbi, sizeof(mbi))
            && mbi.State == MEM_FREE && mbi.RegionSize >= size) {
            auto p = VirtualAlloc(mbi.BaseAddress, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (p) return (uintptr_t)p;
        }
    }
    return (uintptr_t)VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
}

bool Detour::Install(uintptr_t target, uintptr_t detour) {
    if (m_installed) return false;
    m_target = target; m_detour = detour;
    ScopedProtection prot(target, JMP_SIZE);
    memcpy(m_originalBytes, (void*)target, JMP_SIZE);
    m_trampoline = AllocNear(target, JMP_SIZE + JMP_SIZE);
    if (!m_trampoline) return false;
    auto tramp = (uint8_t*)m_trampoline;
    memcpy(tramp, m_originalBytes, JMP_SIZE);
    int32_t back = (int32_t)((target + JMP_SIZE) - (m_trampoline + JMP_SIZE + JMP_SIZE));
    tramp[JMP_SIZE] = 0xE9;
    *(int32_t*)(tramp + JMP_SIZE + 1) = back;
    auto tgt = (uint8_t*)target;
    int32_t fwd = (int32_t)(detour - (target + JMP_SIZE));
    tgt[0] = 0xE9;
    *(int32_t*)(tgt + 1) = fwd;
    FlushInstructionCache(GetCurrentProcess(), (LPCVOID)target, JMP_SIZE);
    m_installed = true; return true;
}

bool Detour::Remove() {
    if (!m_installed) return false;
    ScopedProtection prot(m_target, JMP_SIZE);
    memcpy((void*)m_target, m_originalBytes, JMP_SIZE);
    FlushInstructionCache(GetCurrentProcess(), (LPCVOID)m_target, JMP_SIZE);
    m_installed = false; return true;
}

ScopedProtection::ScopedProtection(uintptr_t addr, size_t sz, DWORD prot)
    : m_addr(addr), m_sz(sz) {
    m_ok = VirtualProtect((LPVOID)addr, sz, prot, &m_old) != FALSE;
}

ScopedProtection::~ScopedProtection() {
    if (m_ok) VirtualProtect((LPVOID)m_addr, m_sz, m_old, &m_old);
}

}
