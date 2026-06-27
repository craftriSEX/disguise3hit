#include <windows.h>
#include <cstdio>
#include "hit3fix.h"

static void OpenConsole() {
    AllocConsole();
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    SetConsoleTitleA("discord minhook.h");
}

BOOL APIENTRY DllMain(HMODULE mod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(mod);
        OpenConsole();
        printf("[@minhook.h] injected\n");
        hit3fix::Initialize();
    } else if (reason == DLL_PROCESS_DETACH) {
        hit3fix::Shutdown();
    }
    return TRUE;
}
