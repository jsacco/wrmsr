// Modified by jsacco <jsacco@exploitpack.com>
// https://exploitpack.com

#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <tuple>
#include <stdexcept>
#include <chrono>
#include <thread>
#include "loadup.hpp"
#include <winternl.h>  

extern "C" NTSYSAPI LONG NTAPI RtlGetLastNtStatus();

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS           ((LONG)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL      ((LONG)0xC0000001L)
#endif

// Your driver's IOCTL for writing an MSR
#pragma pack(push, 1)
struct write_msr_t {
    std::uint32_t  reg;
    std::uintptr_t value;
};
#pragma pack(pop)

namespace vdm
{
    // Global handle to the opened device
    inline HANDLE drv_handle = nullptr;

    // -------------------------
    // Helpers
    // -------------------------

    // Read a whole file into memory (Unicode path)
    inline std::vector<std::uint8_t> ReadAllBytesW(const std::wstring& path)
    {
        HANDLE h = ::CreateFileW(path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("CreateFileW failed, GLE=" + std::to_string(GetLastError()));
        }

        LARGE_INTEGER sz{};
        if (!::GetFileSizeEx(h, &sz)) {
            DWORD err = GetLastError();
            ::CloseHandle(h);
            throw std::runtime_error("GetFileSizeEx failed, GLE=" + std::to_string(err));
        }
        if (sz.QuadPart <= 0 || static_cast<unsigned long long>(sz.QuadPart) > static_cast<unsigned long long>(SIZE_T(-1))) {
            ::CloseHandle(h);
            throw std::runtime_error("Unsupported file size");
        }

        std::vector<std::uint8_t> buf;
        buf.resize(static_cast<size_t>(sz.QuadPart));

        DWORD total = 0;
        while (total < buf.size()) {
            DWORD got = 0;
            if (!::ReadFile(h, buf.data() + total, static_cast<DWORD>(buf.size() - total), &got, nullptr)) {
                DWORD err = GetLastError();
                ::CloseHandle(h);
                throw std::runtime_error("ReadFile failed, GLE=" + std::to_string(err));
            }
            if (got == 0) break;
            total += got;
        }
        ::CloseHandle(h);

        if (total != buf.size()) {
            throw std::runtime_error("Short read");
        }
        return buf;
    }

    // Small helper: ANSI -> Unicode for building \\.\SYMLINK
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

    inline std::string ToNarrow(const std::wstring& ws) {
        if (ws.empty()) return {};
        int n = WideCharToMultiByte(CP_ACP, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string s; s.resize(n ? (n - 1) : 0);
        if (n > 1) WideCharToMultiByte(CP_ACP, 0, ws.c_str(), -1, &s[0], n, nullptr, nullptr);
        return s;
    }

    // Enable SeLoadDriverPrivilege (for NtUnloadDriver path)
    inline bool EnablePrivilege(LPCWSTR name)
    {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            return false;

        LUID luid{};
        bool ok = LookupPrivilegeValueW(nullptr, name, &luid) != FALSE;
        if (ok) {
            TOKEN_PRIVILEGES tp{};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
            ok = (GetLastError() == ERROR_SUCCESS);
        }
        CloseHandle(hToken);
        return ok;
    }

    // SCM stop + delete with retries. Returns STATUS_SUCCESS on success, else STATUS_UNSUCCESSFUL.
    inline LONG ScmStopAndDeleteA(const std::string& svcNameA)
    {
        std::wstring svcName = ToWide(svcNameA);

        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scm) return STATUS_UNSUCCESSFUL;

        SC_HANDLE svc = OpenServiceW(scm, svcName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
        if (!svc) { CloseServiceHandle(scm); return STATUS_UNSUCCESSFUL; }

        SERVICE_STATUS_PROCESS ssp{};
        DWORD bytes = 0;

        // Try to stop (best effort)
        ControlService(svc, SERVICE_CONTROL_STOP, reinterpret_cast<LPSERVICE_STATUS>(&ssp));

        // Wait until stopped (up to ~3s)
        for (int i = 0; i < 30; ++i) {
            if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytes))
                break;
            if (ssp.dwCurrentState == SERVICE_STOPPED) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        // Delete the service
        BOOL delOk = DeleteService(svc);

        CloseServiceHandle(svc);
        CloseServiceHandle(scm);

        return delOk ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    inline std::tuple<HANDLE, std::string, LONG> load_drv_from_file(const std::wstring& sysPath, const std::wstring& wkey)
    {
        // Read bytes from disk
        std::vector<std::uint8_t> image = ReadAllBytesW(sysPath);

        // Call your existing loader that takes (ptr, size).
        // NOTE: we use the EXACT key the loader returns to open \\.\<key> and to unload later.
        const auto load_ret = driver::load(image.data(), image.size());
        const LONG status = load_ret.first;
        std::string key;
        std::wstring lowerKey = wkey;
        std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(),[](wchar_t c) { return towlower(c); });
        if (lowerKey.find(L"none") != std::wstring::npos) {
            key = load_ret.second;
        }
        else {
            key = ToNarrow(wkey);
        }


        if (status != STATUS_SUCCESS) {
            return std::make_tuple(HANDLE(nullptr), std::string(), status);
        }

        // Open \\.\<key>
        std::wstring wsymlink = L"\\\\.\\" + ToWide(key);

        // Optional tiny retry window: device object may appear a moment after the service starts.
        HANDLE hDev = INVALID_HANDLE_VALUE;
        for (int i = 0; i < 30; ++i) { // ~300 ms total
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

        vdm::drv_handle = (hDev == INVALID_HANDLE_VALUE) ? nullptr : hDev;
        return std::make_tuple(vdm::drv_handle, key, status);
    }

    // -------------------------
    // Unload
    // -------------------------
    inline LONG unload_drv(HANDLE handle, const std::string& drv_key)
    {
        // Close the device handle first (if any) to let the driver unload cleanly.
        if (handle && handle != INVALID_HANDLE_VALUE) {
            ::CloseHandle(handle);
        }
        // clear the global so future calls don’t use a stale handle.
        vdm::drv_handle = nullptr;

        // Give the driver a moment to drop last references (completions, worker items, etc.)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // First attempt: your original loader’s uninstall path
        {
            const LONG st = driver::unload(drv_key);
            if (st == STATUS_SUCCESS) {
                return STATUS_SUCCESS;
            }
        }

        // Second attempt: SCM stop + delete (in case your loader’s helper couldn’t finish)
        {
            const LONG st = ScmStopAndDeleteA(drv_key);
            if (st == STATUS_SUCCESS) return STATUS_SUCCESS;
        }

        // Final attempt: direct NtUnloadDriver using the service registry path
        // Requires SeLoadDriverPrivilege
        EnablePrivilege(L"SeLoadDriverPrivilege");

        std::wstring regPath =
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"
            + ToWide(drv_key);

        UNICODE_STRING us{};
        us.Buffer = const_cast<PWSTR>(regPath.c_str());
        us.Length = static_cast<USHORT>(regPath.size() * sizeof(wchar_t));
        us.MaximumLength = us.Length;

        LONG stNt = NtUnloadDriver(&us);
        if (stNt == STATUS_SUCCESS) {
            // Some systems keep the service marked for delete a bit; small wait helps the next load.
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            return STATUS_SUCCESS;
        }

        // Give a tiny back-off and one more SCM delete try (helps on races)
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        if (ScmStopAndDeleteA(drv_key) == STATUS_SUCCESS)
            return STATUS_SUCCESS;

        return stNt ? stNt : STATUS_UNSUCCESSFUL;
    }

    // -------------------------
    // Write MSR through your driver
    // -------------------------
    inline bool writemsr(std::uint32_t reg, std::uintptr_t value, DWORD ioctl_code)
    {
        if (!vdm::drv_handle || vdm::drv_handle == INVALID_HANDLE_VALUE) {
            return false;
        }

        write_msr_t io_data{ reg, value };
        DWORD bytes_handled = 0;

        return ::DeviceIoControl(
            vdm::drv_handle,
            ioctl_code,
            &io_data, static_cast<DWORD>(sizeof io_data),
            &io_data, static_cast<DWORD>(sizeof io_data),
            &bytes_handled,
            nullptr
        ) != FALSE;
    }
}
