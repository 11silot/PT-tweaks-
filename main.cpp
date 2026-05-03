#include <windows.h>
#include <wininet.h>
#include <urlmon.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <vector>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "iphlpapi.lib")

static void SetBlue() {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_INTENSITY);
}

static void SetWhite() {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
}

static void PrintSep() {
    SetBlue();
    std::cout << "======================================================" << std::endl;
}

static void PrintHeader(const char* title) {
    std::cout << std::endl;
    PrintSep();
    SetBlue();
    std::cout << " " << title << std::endl;
    PrintSep();
    SetWhite();
    std::cout << std::endl;
}

static std::string GetHWID() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        char val[256] = {};
        DWORD sz = sizeof(val);
        DWORD type = REG_SZ;
        RegQueryValueExA(hKey, "MachineGuid", nullptr, &type, (LPBYTE)val, &sz);
        RegCloseKey(hKey);
        std::string guid(val);
        std::string filtered;
        for (char c : guid) if (c != '-') filtered += (char)toupper(c);
        if (filtered.size() >= 16) return filtered.substr(0, 16);
        return filtered;
    }
    PIP_ADAPTER_INFO info = nullptr;
    ULONG bufLen = sizeof(IP_ADAPTER_INFO);
    info = (PIP_ADAPTER_INFO)malloc(bufLen);
    if (GetAdaptersInfo(info, &bufLen) == ERROR_BUFFER_OVERFLOW) {
        free(info);
        info = (PIP_ADAPTER_INFO)malloc(bufLen);
    }
    std::string hwid;
    if (GetAdaptersInfo(info, &bufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO a = info;
        while (a) {
            if (a->Type == MIB_IF_TYPE_ETHERNET || a->Type == IF_TYPE_IEEE80211) {
                char buf[64];
                snprintf(buf, sizeof(buf), "%02X%02X%02X%02X%02X%02X",
                    a->Address[0], a->Address[1], a->Address[2],
                    a->Address[3], a->Address[4], a->Address[5]);
                hwid = buf;
                break;
            }
            a = a->Next;
        }
    }
    if (info) free(info);
    return hwid.empty() ? "UNKNOWN" : hwid;
}

static std::string GetExeDir() {
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    std::string s(path);
    size_t pos = s.find_last_of("\\/");
    return (pos != std::string::npos) ? s.substr(0, pos) : s;
}

static void RunCmd(const std::string& cmd) {
    STARTUPINFOA si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    std::string c = "cmd.exe /c " + cmd;
    std::vector<char> buf(c.begin(), c.end());
    buf.push_back(0);
    CreateProcessA(nullptr, buf.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

static void LaunchExe(const std::string& path) {
    STARTUPINFOA si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    std::vector<char> buf(path.begin(), path.end());
    buf.push_back(0);
    if (CreateProcessA(nullptr, buf.data(), nullptr, nullptr, FALSE,
        0, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

static bool DownloadFileDirect(const std::string& url, const std::string& dest) {
    HINTERNET hInet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hInet) return false;

    HINTERNET hUrl = InternetOpenUrlA(hInet, url.c_str(), nullptr, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) {
        InternetCloseHandle(hInet);
        return false;
    }

    HANDLE hFile = CreateFileA(dest.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInet);
        return false;
    }

    char buf[65536];
    DWORD read = 0;
    DWORD totalBytes = 0;
    while (InternetReadFile(hUrl, buf, sizeof(buf), &read) && read > 0) {
        DWORD written;
        WriteFile(hFile, buf, read, &written, nullptr);
        totalBytes += read;
    }

    CloseHandle(hFile);
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInet);

    if (totalBytes < 1024) {
        DeleteFileA(dest.c_str());
        return false;
    }
    return true;
}

static bool FolderExists(const std::string& path) {
    DWORD attr = GetFileAttributesA(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY));
}

static bool FileExists(const std::string& path) {
    DWORD attr = GetFileAttributesA(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

static bool EnsureDependencies(const std::string& exeDir) {
    std::vector<std::string> needed = {
        "dControl.exe", "OOSU10.exe", "nvidiaProfileInspector.exe",
        "NSudoLG.exe", "dpclat.exe", "setup.exe", "SetTimerResolution.exe"
    };

    for (auto& f : needed) {
        if (!FileExists(exeDir + "\\" + f)) {
            std::cout << " [*] " << f << " not found, downloading dependencies..." << std::endl;

            std::string zipPath = exeDir + "\\dependencies.zip";
            const char* url = "https://download1638.mediafire.com/cvh0010iwnhgTH3jnhlKGBaUknFpcPPLgevBMyLDpdXFquMZowgVS7iD8uGnflZueRLY1xnR05Ar9F-jt-6bzPQ7qgsvrEqRXSaHtMeWpfwmWgTEFLP1XznogQlHomLJrz3Fcp3G1Q4ihb8bXNEBrF7II-KepTublrweuyQ1tkKOE4w/lbx68xlo08vxxjh/dependencies.zip";

            std::cout << " [*] Downloading..." << std::endl;
            HRESULT hr = URLDownloadToFileA(nullptr, url, zipPath.c_str(), 0, nullptr);
            if (hr != S_OK || !FileExists(zipPath)) {
                if (!DownloadFileDirect(url, zipPath)) {
                    std::cout << " [!] Download failed." << std::endl;
                    return false;
                }
            }

            std::cout << " [*] Extracting..." << std::endl;
            std::string psCmd = "powershell -NoProfile -NonInteractive -Command \""
                "Add-Type -Assembly System.IO.Compression.FileSystem; "
                "[System.IO.Compression.ZipFile]::ExtractToDirectory('" + zipPath + "', '" + exeDir + "')\"";
            RunCmd(psCmd);

            if (!FileExists(exeDir + "\\dControl.exe")) {
                std::string psCmd2 = "powershell -NoProfile -NonInteractive -Command \""
                    "Expand-Archive -LiteralPath '" + zipPath + "' -DestinationPath '" + exeDir + "' -Force\"";
                RunCmd(psCmd2);
            }

            DeleteFileA(zipPath.c_str());

            std::string subDir = exeDir + "\\dependencies";
            if (FolderExists(subDir)) {
                for (auto& sf : needed) {
                    std::string src = subDir + "\\" + sf;
                    std::string dst = exeDir + "\\" + sf;
                    if (FileExists(src) && !FileExists(dst))
                        MoveFileA(src.c_str(), dst.c_str());
                }
                RemoveDirectoryA(subDir.c_str());
            }

            break;
        }
    }
    return true;
}

static void CleanupExes(const std::string& exeDir) {
    std::vector<std::string> toDelete = {
        "dControl.exe", "OOSU10.exe", "nvidiaProfileInspector.exe",
        "NSudoLG.exe", "dpclat.exe", "setup.exe", "SetTimerResolution.exe"
    };
    for (auto& f : toDelete)
        DeleteFileA((exeDir + "\\" + f).c_str());
}

static void ApplyCTTTweaks() {
    HKEY hKey;
    DWORD zero = 0;
    DWORD one = 1;
    DWORD two = 2;
    DWORD ffffffff = 0xffffffff;

    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\System", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "EnableActivityFeed", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegSetValueExA(hKey, "PublishUserActivities", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegSetValueExA(hKey, "UploadUserActivities", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegCloseKey(hKey);

    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "Value", 0, REG_SZ, (LPBYTE)"Deny", 5);
    RegCloseKey(hKey);
    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Sensor\\Overrides\\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "SensorPermissionState", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegCloseKey(hKey);
    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\lfsvc\\Service\\Configuration", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "Status", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegCloseKey(hKey);
    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\Maps", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "AutoUpdateEnabled", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegCloseKey(hKey);

    RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Windows\\Explorer", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "DisableNotificationCenter", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegCloseKey(hKey);
    RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "ToastEnabled", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegCloseKey(hKey);

    RunCmd("powershell -NoProfile -Command \"Remove-Item -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\StoragePolicy' -Recurse -ErrorAction SilentlyContinue\"");

    RegCreateKeyExA(HKEY_CURRENT_USER, "Control Panel\\Accessibility\\StickyKeys", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "Flags", 0, REG_SZ, (LPBYTE)"506", 4);
    RegCloseKey(hKey);

    RegCreateKeyExA(HKEY_USERS, ".DEFAULT\\Control Panel\\Keyboard", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "InitialKeyboardIndicators", 0, REG_SZ, (LPBYTE)"2", 2);
    RegCloseKey(hKey);

    RunCmd("powershell -NoProfile -Command \"New-Item -Path 'HKCU:\\Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}' -Name 'InprocServer32' -Force | New-ItemProperty -Name '(default)' -Value '' -PropertyType String -Force\"");

    RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "HideFileExt", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegSetValueExA(hKey, "Hidden", 0, REG_DWORD, (LPBYTE)&one, sizeof(one));
    RegSetValueExA(hKey, "TaskbarDa", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegSetValueExA(hKey, "ShowTaskViewButton", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegSetValueExA(hKey, "SearchboxTaskbarMode", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegSetValueExA(hKey, "ListviewAlphaSelect", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegSetValueExA(hKey, "ListviewShadow", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegSetValueExA(hKey, "TaskbarAnimations", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegCloseKey(hKey);

    RegCreateKeyExA(HKEY_CURRENT_USER, "Control Panel\\Desktop", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "DragFullWindows", 0, REG_SZ, (LPBYTE)"0", 2);
    RegSetValueExA(hKey, "MenuShowDelay", 0, REG_SZ, (LPBYTE)"0", 2);
    RegSetValueExA(hKey, "UserPreferencesMask", 0, REG_BINARY, (LPBYTE)"\x90\x12\x03\x80\x10\x00\x00\x00", 8);
    RegCloseKey(hKey);
    RegCreateKeyExA(HKEY_CURRENT_USER, "Control Panel\\Desktop\\WindowMetrics", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "MinAnimate", 0, REG_SZ, (LPBYTE)"0", 2);
    RegCloseKey(hKey);
    RegCreateKeyExA(HKEY_CURRENT_USER, "Control Panel\\Keyboard", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "KeyboardDelay", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegCloseKey(hKey);
    RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "VisualFXSetting", 0, REG_DWORD, (LPBYTE)&two, sizeof(two));
    RegCloseKey(hKey);
    RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\DWM", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "EnableAeroPeek", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegCloseKey(hKey);
    RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Search", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "BingSearchEnabled", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegCloseKey(hKey);

    RegCreateKeyExA(HKEY_CURRENT_USER, "System\\GameConfigStore", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "GameDVR_FSEBehavior", 0, REG_DWORD, (LPBYTE)&two, sizeof(two));
    RegSetValueExA(hKey, "GameDVR_Enabled", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegSetValueExA(hKey, "GameDVR_DXGIHonorFSEWindowsCompatible", 0, REG_DWORD, (LPBYTE)&one, sizeof(one));
    RegSetValueExA(hKey, "GameDVR_HonorUserFSEBehaviorMode", 0, REG_DWORD, (LPBYTE)&one, sizeof(one));
    RegSetValueExA(hKey, "GameDVR_EFSEFeatureFlags", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegCloseKey(hKey);
    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "AllowGameDVR", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegCloseKey(hKey);

    RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\GameBar", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "AllowAutoGameMode", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegSetValueExA(hKey, "AutoGameModeEnabled", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegCloseKey(hKey);

    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "HwSchMode", 0, REG_DWORD, (LPBYTE)&two, sizeof(two));
    RegCloseKey(hKey);

    RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "EnableTransparency", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegCloseKey(hKey);

    RegCreateKeyExA(HKEY_CURRENT_USER, "Control Panel\\Mouse", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "MouseSpeed", 0, REG_SZ, (LPBYTE)"0", 2);
    RegSetValueExA(hKey, "MouseThreshold1", 0, REG_SZ, (LPBYTE)"0", 2);
    RegSetValueExA(hKey, "MouseThreshold2", 0, REG_SZ, (LPBYTE)"0", 2);
    RegCloseKey(hKey);

    RunCmd("powercfg.exe /hibernate off");

    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "DisabledComponents", 0, REG_DWORD, (LPBYTE)&ffffffff, sizeof(ffffffff));
    RegCloseKey(hKey);
    RunCmd("powershell -Command \"Disable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6\"");

    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "EnableLUA", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegCloseKey(hKey);

    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\Session Manager\\Power", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
    RegSetValueExA(hKey, "HibernateEnabled", 0, REG_DWORD, (LPBYTE)&zero, sizeof(zero));
    RegCloseKey(hKey);
}

static void ApplyServiceTweaks() {
    std::vector<std::string> disabled = {
        "AJRouter","AppVClient","AssignedAccessManagerSvc","DiagTrack","DialogBlockingService",
        "MSDTC","NetTcpPortSharing","RemoteAccess","RemoteRegistry","UevAgentService",
        "shpamsvc","smphost","ssh-agent","tzautoupdate","uhssvc",
        "AppIDSvc","AppMgmt","AppReadiness","AppXSvc","Appinfo","AxInstSV","BDESVC",
        "BTAGService","BcastDVRUserService_dc2a4","Browser","CDPSvc","COMSysApp",
        "CaptureService_dc2a4","CertPropSvc","ClipSVC","ConsentUxUserSvc_dc2a4",
        "CredentialEnrollmentManagerUserSvc_dc2a4","CscService","DcpSvc","DevQueryBroker",
        "DeviceAssociationBrokerSvc_dc2a4","DeviceAssociationService","DeviceInstall",
        "DevicePickerUserSvc_dc2a4","DevicesFlowUserSvc_dc2a4","DisplayEnhancementService",
        "DmEnrollmentSvc","DsSvc","DsmSvc","EapHost","EntAppSvc","FDResPub","FrameServer",
        "FrameServerMonitor","GraphicsPerfSvc","HvHost","IEEtwCollectorService","IKEEXT",
        "InstallService","InventorySvc","IpxlatCfgSvc","KtmRm","LicenseManager","LxpSvc",
        "MSiSCSI","McpManagementService","MessagingService_dc2a4","MixedRealityOpenXRSvc",
        "MsKeyboardFilter","NPSMSvc_dc2a4","NaturalAuthentication","NcaSvc","NcbService",
        "NcdAutoSetup","NetSetupSvc","Netlogon","NgcCtnrSvc","NgcSvc","NlaSvc",
        "P9RdrService_dc2a4","PNRPAutoReg","PNRPsvc","PcaSvc","PeerDistSvc",
        "PenService_dc2a4","PerfHost","PhoneSvc","PimIndexMaintenanceSvc_dc2a4","PolicyAgent",
        "PrintNotify","PrintWorkflowUserSvc_dc2a4","PushToInstall","QWAVE","RasAuto","RasMan",
        "RetailDemo","RmSvc","RpcLocator","SCPolicySvc","SCardSvr","SDRSVC","SEMgrSvc",
        "SNMPTRAP","SNMPTrap","SSDPSRV","ScDeviceEnum","SecurityHealthService","Sense",
        "SensorDataService","SensorService","SensrSvc","SessionEnv","SharedAccess",
        "SharedRealitySvc","SmsRouter","SstpSvc","StateRepository","StiSvc","StorSvc",
        "TabletInputService","TapiSrv","TextInputManagementService","WbioSrvc","WdNisSvc"
    };
    std::vector<std::string> manual = {
        "HomeGroupListener","HomeGroupProvider","DoSvc","MapsBroker","WSearch","AppMgmt"
    };
    std::vector<std::string> delayedAuto = {
        "sppsvc"
    };
    for (auto& s : disabled) RunCmd("sc config \"" + s + "\" start= disabled 2>nul");
    for (auto& s : manual)   RunCmd("sc config \"" + s + "\" start= demand 2>nul");
    for (auto& s : delayedAuto) RunCmd("sc config \"" + s + "\" start= delayed-auto 2>nul");
}

static void ApplyPTTweaks() {
    std::vector<std::string> cmds = {
        "schtasks /Change /TN \"MicrosoftEdgeUpdateTaskMachineUA\" /Disable 2>nul",
        "schtasks /Change /TN \"MicrosoftEdgeUpdateTaskMachineCore\" /Disable 2>nul",
        "schtasks /Change /TN \"\\Microsoft\\Windows\\UNP\\RunUpdateNotificationMgr\" /Disable 2>nul",
        "schtasks /Change /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Maintenance Work\" /Disable 2>nul",
        "schtasks /Change /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan\" /Disable 2>nul",
        "schtasks /Change /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan Static Task\" /Disable 2>nul",
        "schtasks /Change /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Wake To Work\" /Disable 2>nul",
        "schtasks /Change /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Work\" /Disable 2>nul",
        "schtasks /Change /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\Start Oobe Expedite Work\" /Disable 2>nul",
        "schtasks /Change /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\Report policies\" /Disable 2>nul",
        "schtasks /Change /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\StartOobeAppsScan_LicenseAccepted\" /Disable 2>nul",
        "schtasks /Change /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\StartOobeAppsScanAfterUpdate\" /Disable 2>nul",
        "schtasks /Change /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\USO_UxBroker\" /Disable 2>nul",
        "schtasks /Change /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\UUS Failover Task\" /Disable 2>nul",
        "schtasks /Delete /TN \"MicrosoftEdgeUpdateTaskMachineUA\" /F 2>nul",
        "schtasks /Delete /TN \"MicrosoftEdgeUpdateTaskMachineCore\" /F 2>nul",
        "schtasks /Delete /TN \"\\Microsoft\\Windows\\UNP\\RunUpdateNotificationMgr\" /F 2>nul",
        "schtasks /Delete /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Maintenance Work\" /F 2>nul",
        "schtasks /Delete /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan\" /F 2>nul",
        "schtasks /Delete /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan Static Task\" /F 2>nul",
        "schtasks /Delete /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Wake To Work\" /F 2>nul",
        "schtasks /Delete /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Work\" /F 2>nul",
        "schtasks /Delete /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\Start Oobe Expedite Work\" /F 2>nul",
        "schtasks /Delete /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\Report policies\" /F 2>nul",
        "schtasks /Delete /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\StartOobeAppsScan_LicenseAccepted\" /F 2>nul",
        "schtasks /Delete /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\StartOobeAppsScanAfterUpdate\" /F 2>nul",
        "schtasks /Delete /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\USO_UxBroker\" /F 2>nul",
        "schtasks /Delete /TN \"\\Microsoft\\Windows\\UpdateOrchestrator\\UUS Failover Task\" /F 2>nul"
    };
    for (auto& c : cmds) RunCmd(c);
}

static void ApplyProcessDestroyer() {
    std::vector<std::string> cmds = {
        "taskkill /f /im ctfmon.exe 2>nul",
        "ren \"C:\\Windows\\System32\\ctfmon.exe\" \"ctfmon.exee\" 2>nul",
        "taskkill /f /im backgroundTaskHost.exe 2>nul",
        "ren \"C:\\Windows\\System32\\backgroundTaskHost.exe\" \"backgroundTaskHost.exee\" 2>nul",
        "taskkill /f /im TextInputHost.exe 2>nul",
        "ren \"C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\TextInputHost.exe\" \"TextInputHost.exee\" 2>nul",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e967-e325-11ce-bfc1-08002be10318}\" /v \"LowerFilters\" /t REG_MULTI_SZ /d \"\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e96c-e325-11ce-bfc1-08002be10318}\" /v \"UpperFilters\" /t REG_MULTI_SZ /d \"\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{6bdd1fc6-810f-11d0-bec7-08002be2092f}\" /v \"UpperFilters\" /t REG_MULTI_SZ /d \"\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{71a27cdd-812a-11d0-bec7-08002be2092f}\" /v \"LowerFilters\" /t REG_MULTI_SZ /d \"\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}\" /v \"UpperFilters\" /t REG_MULTI_SZ /d \"\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\NVDisplay.ContainerLocalSystem\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\BFE\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\mpssvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\webthreatdefsvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WpnUserService\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SystemEventsBroker\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventSystem\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\AppIDSvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\wscsvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\NgcCtnrSvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\TimeBrokerSvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinHttpAutoProxySvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\QWAVE\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\seclogon\" /v \"Start\" /t REG_DWORD /d \"3\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SENS\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Schedule\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\webthreatdefusersvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\hidserv\" /v \"Start\" /t REG_DWORD /d \"3\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\NgcSvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\sppsvc\" /v \"Start\" /t REG_DWORD /d \"3\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\AppXSvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\edgeupdate\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\edgeupdatem\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\MicrosoftEdgeElevationService\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WdNisSvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SamSs\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\VaultSvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LicenseManager\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\gpsvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\PlugPlay\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SgrmBroker\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\msiserver\" /v \"Start\" /t REG_DWORD /d \"4\" /f"
    };
    for (auto& c : cmds) RunCmd(c);
}

static void ApplySoundTweaks() {
    std::vector<std::string> cmds = {
        "taskkill /F /IM RtkAudUService64.exe 2>nul",
        "net stop \"RtkAudioUniversalService\" 2>nul",
        "sc config RtkAudioUniversalService start=disabled 2>nul",
        "taskkill /f /im SECOMNService.exe 2>nul",
        "taskkill /f /im SECOCL.exe 2>nul",
        "net stop \"SECOMNService\" 2>nul",
        "sc config SECOMNService start=disabled 2>nul",
        "rd /s /q \"C:\\Windows\\System32\\SECOMN64.exe\" 2>nul",
        "rd /s /q \"C:\\Windows\\System32\\SECOCL64.exe\" 2>nul",
        "rd /s /q \"C:\\Windows\\System32\\SECCNH64.exe\" 2>nul",
        "taskkill /f /im VSHelper.exe 2>nul",
        "taskkill /f /im VSSrv.exe 2>nul",
        "net stop \"VSSrv\" 2>nul",
        "sc config VSSrv start=disabled 2>nul",
        "rd /s /q \"C:\\Windows\\System32\\VSHelper.exe\" 2>nul",
        "rd /s /q \"C:\\Windows\\System32\\VSSrv.exe\" 2>nul"
    };
    for (auto& c : cmds) RunCmd(c);
}

static void ApplyAMDTweaks() {
    std::vector<std::string> cmds = {
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\AMD Crash Defender Service\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\AMD External Events Utility\" /v \"Start\" /t REG_DWORD /d \"4\" /f",
        "reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\AUEPLauncher\" /v \"Start\" /t REG_DWORD /d \"4\" /f"
    };
    for (auto& c : cmds) RunCmd(c);
}

static void ApplyTaskDestroyer() {
    char windir[MAX_PATH];
    GetWindowsDirectoryA(windir, MAX_PATH);
    std::string tasks = std::string(windir) + "\\System32\\Tasks";
    std::vector<std::string> cmds = {
        "reg export \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\" \"C:\\PT\\Task Destroyer\\Reg Backup\\TaskSchedulerBackup.reg\" /y 2>nul",
        "xcopy \"" + tasks + "\" \"C:\\PT\\Task Destroyer\\Task Backup\\Tasks\" /E /I /H /Y 2>nul",
        "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskStateFlags\" /f 2>nul",
        "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\" /f 2>nul",
        "rd /s /q \"" + tasks + "\" 2>nul"
    };
    for (auto& c : cmds) RunCmd(c);
}

int main() {
    SetConsoleTitleA("PT TWEAKS");
    SetWhite();

    PrintHeader("PT TWEAKS  -  Terms of Use");
    std::cout << " By using this tool you agree that:" << std::endl;
    std::cout << std::endl;
    std::cout << " - Your HWID and PC name will be sent to the developer for license verification." << std::endl;
    std::cout << " - This tool makes system changes." << std::endl;
    std::cout << " - Redistribution is not allowed." << std::endl;
    std::cout << std::endl;
    std::cout << " Accept terms? (Y/N): ";

    std::string answer;
    std::getline(std::cin, answer);
    if (answer.empty() || (answer[0] != 'Y' && answer[0] != 'y')) {
        std::cout << std::endl << " Exiting..." << std::endl;
        Sleep(1500);
        return 0;
    }

    PrintHeader("PT TWEAKS  -  License Verification");

    std::string hwid = GetHWID();
    std::cout << " Your HWID: " << hwid << std::endl;
    std::cout << std::endl;
    std::cout << " Enter License Key: ";

    std::string key;
    std::getline(std::cin, key);

    if (key != "silot") {
        std::cout << std::endl;
        std::cout << " Invalid license key. Exiting..." << std::endl;
        Sleep(2000);
        return 1;
    }

    std::string exeDir = GetExeDir();

    EnsureDependencies(exeDir);

    PrintHeader("PT TWEAKS  -  Applying Tweaks");

    std::cout << " [*] Running CTT Tweaks..." << std::endl;
    ApplyCTTTweaks();

    std::cout << " [*] Running Service Tweaks..." << std::endl;
    ApplyServiceTweaks();

    std::cout << " [*] Running PT Tweaks..." << std::endl;
    ApplyPTTweaks();

    std::cout << " [*] Running Process Destroyer..." << std::endl;
    ApplyProcessDestroyer();

    std::cout << " [*] Running Sound Tweaks..." << std::endl;
    ApplySoundTweaks();

    std::cout << " [*] Running AMD Tweaks..." << std::endl;
    ApplyAMDTweaks();

    std::cout << " [*] Running Task Destroyer..." << std::endl;
    ApplyTaskDestroyer();

    std::cout << " [*] Launching DControl..." << std::endl;
    LaunchExe("\"" + exeDir + "\\dControl.exe\"");

    std::cout << " [*] Launching OO Shutup 10..." << std::endl;
    LaunchExe("\"" + exeDir + "\\OOSU10.exe\"");

    std::cout << " [*] Launching Nvidia Profile Inspector..." << std::endl;
    LaunchExe("\"" + exeDir + "\\nvidiaProfileInspector.exe\"");

    std::cout << std::endl;
    std::cout << " All tweaks applied successfully." << std::endl;
    std::cout << std::endl;

    CleanupExes(exeDir);

    std::cout << " Press Enter to exit..." << std::endl;
    std::string dummy;
    std::getline(std::cin, dummy);
    return 0;
}
