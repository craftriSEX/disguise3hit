#pragma once
#include <windows.h>
#include <cstdint>

namespace memory {

class Detour {
public:
    Detour() = default;
    ~Detour() { Remove(); }
    bool Install(uintptr_t target, uintptr_t detour);
    bool Remove();
    template<typename T> T GetOriginal() const { return reinterpret_cast<T>(m_trampoline); }
private:
    static constexpr int JMP_SIZE = 5;
    uintptr_t m_target = 0;
    uintptr_t m_detour = 0;
    uintptr_t m_trampoline = 0;
    uint8_t m_originalBytes[JMP_SIZE]{};
    bool m_installed = false;
};

class ScopedProtection {
public:
    ScopedProtection(uintptr_t addr, size_t sz, DWORD prot = PAGE_EXECUTE_READWRITE);
    ~ScopedProtection();
    ScopedProtection(const ScopedProtection&) = delete;
    ScopedProtection& operator=(const ScopedProtection&) = delete;
    ScopedProtection(ScopedProtection&&) = delete;
    ScopedProtection& operator=(ScopedProtection&&) = delete;
private:
    uintptr_t m_addr; size_t m_sz; DWORD m_old; bool m_ok = false;
};

}
