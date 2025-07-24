---
title: Extracting Windows WiFi Profiles
date: 2025-03-19
categories: [windows,cpp,wifi,networking]
tags: [windows,cpp,wifi,networking]
excerpt: 
---
## wifiExtract

The other day my grandmother forgot her Windows WiFi SSID and password when she wanted to share it with a friend. So I thought if I could just automate the retrieval of her wireless profiles, she would never forget them again in the future.

It turns out, the Windows API offers a nice way to enumerate WLAN information. First, we open a handle to the WLAN system by first calling the `WlanOpenHandle` function, which we can then use to enumerate WLAN interfaces with the `WlanEnumInterfaces` function. [^1]



```Cpp
DWORD WlanEnumInterfaces(
  [in]  HANDLE                    hClientHandle,
  [in]  PVOID                     pReserved,
  [out] PWLAN_INTERFACE_INFO_LIST *ppInterfaceList
);
```

Once we've found a wireless network interface, we can iterate through its profiles. WLAN profiles are stored in XML format. We can see an example profile here.

```text
>type %SYSTEMDRIVE%"\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{FA6CC5AF-E3EC-4CDB-A7E9-014E5352F6FA}\{A181B5A9-A72D-445B-948A-DA29AC041866}.xml"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
        <name>networked</name>
        <SSIDConfig>
                <SSID>
                        <hex>6E6574776F726B6564</hex>
                        <name>networked</name>
                </SSID>
                <nonBroadcast>false</nonBroadcast>
        </SSIDConfig>
        <connectionType>ESS</connectionType>
        <connectionMode>manual</connectionMode>
        <MSM>
                <security>
                        <authEncryption>
                                <authentication>WPA2PSK</authentication>
                                <encryption>AES</encryption>
                                <useOneX>false</useOneX>
                        </authEncryption>
                        <sharedKey>
                                <keyType>passPhrase</keyType>
                                <protected>true</protected>
                                <keyMaterial>01000000D08C9DDF0115D1118C7A00C04FC297EB01000000C3D1445ECDFED24C989C1BE14BC7ABF5000000000200000000001066000000010000200000007F040AECC06A879362E949BAB5C2810179CABF3300DA399698E4E9D0F8814DD3000000000E80000000020000200000002C48A4A12EABFC325564EC54E086C181A46707218CF19C65151D89430EF5466010000000CC8C4E3C6AACC202F85168DD75B291A5400000004E136AF57200DD275D323E73BBEB2AEABF7AFA8BFEC60B0DA56972203222ABA576E751BF5F5B678CB367A2D6E6272BC691ACCEABDF3959B932EB1C9EE5426065</keyMaterial>
                        </sharedKey>
                </security>
        </MSM>
</WLANProfile>
```

For each WLAN profile, we try to locate the ```<keyMaterial>``` tags, which contain the SSID's passphrase, and get its value. 

But we have to account for the size of the `<keyMaterial>` tag itself when we do our check. So, when we find the tag, we add the size (13) to the beginning marker, as well as subtract the size of the ending marker—ensuring we only extract the passphrase within the key material tags and not any strings or characters from the tags themselves.

Altogether, for each WLAN profile we find, we use `WlanGetProfile` to acquire the SSID, aka the profileName, and its related passphrase.

```Cpp
DWORD WlanGetProfile(
  [in]                HANDLE     hClientHandle,
  [in]                const GUID *pInterfaceGuid,
  [in]                LPCWSTR    strProfileName,
  [in]                PVOID      pReserved,
  [out]               LPWSTR     *pstrProfileXml,
  [in, out, optional] DWORD      *pdwFlags,
  [out, optional]     DWORD      *pdwGrantedAccess
);
```

We decrypt the passphrase on-the-fly by appending the `GET_PLAINTEXT_KEY` flag to the `WlanGetProfile`[^2] function call. 

```cpp
for (DWORD i = 0; i < plist->dwNumberOfItems; ++i) {
        const WLAN_INTERFACE_INFO& interface_info = plist->InterfaceInfo[i];
        PWLAN_PROFILE_INFO_LIST profileList = NULL;

        result = WlanGetProfileList(hClient, &interface_info.InterfaceGuid, NULL, &profileList);
        if (result != ERROR_SUCCESS) {
            error("WlanGetProfileList failed: " + std::to_string(result));
            continue;
        }

        for (DWORD j = 0; j < profileList->dwNumberOfItems; ++j) {
            const WLAN_PROFILE_INFO& profileInfo = profileList->ProfileInfo[j];
            std::wstring profileName(profileInfo.strProfileName);

            LPWSTR xmlProfile = NULL;
            DWORD flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
            result = WlanGetProfile(hClient, &interface_info.InterfaceGuid, profileName.c_str(), NULL, &xmlProfile, &flags, NULL);
            if (result != ERROR_SUCCESS) {
                error("WlanGetProfile failed: " + std::to_string(result));
                continue;
            }

            std::wstring profileXml(xmlProfile);
            size_t key = profileXml.find(L"<keyMaterial>");
            if (key != std::wstring::npos) {
                size_t keyEnd = profileXml.find(L"</keyMaterial>", key);
                if (keyEnd != std::wstring::npos) {
                    std::wstring keyContent = profileXml.substr(key + 13, keyEnd - (key + 13));
                    std::wcout << L"[+] Found Wifi Profile:" << std::endl;
                    std::wcout << L"[+] SSID: " << profileName << std::endl;
                    std::wcout << L"[+] Key: " << keyContent << std::endl;
                    std::wcout << L" " << std::endl;
                }
            }
            else {
                std::wcout << L"[+] Found Wifi Profile:" << std::endl;
                std::wcout << L"[+] SSID: " << profileName << std::endl;
                std::wcout << L"[+] No key material found" << std::endl;
                std::wcout << L" " << std::endl;
            }

 // snipped

 ```


```text
>msbuild wifiExtract\wifiExtract\wifiExtract.vcxproj
MSBuild version 17.13.19+0d9f5a35a for .NET Framework
Build started 3/19/2025 11:49:09 PM.

Project "C:\Users\augur\source\repos\wifiExtract\wifiExtract\wifiExtract.vcxproj" on node 1 (default targets)
.
PrepareForBuild:
  Structured output is enabled. The formatting of compiler diagnostics will reflect the error hierarchy. See
  https://aka.ms/cpp/structured-output for more details.
InitializeBuildStatus:
  Creating "wifiExtract\Debug\wifiExtract.tlog\unsuccessfulbuild" because "AlwaysCreate" was specified.
  Touching "wifiExtract\Debug\wifiExtract.tlog\unsuccessfulbuild".
ClCompile:
  C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\bin\HostX86\x86\CL.exe /c
   /ZI /JMC /nologo /W3 /WX- /diagnostics:column /sdl /Od /Oy- /D WIN32 /D _DEBUG /D _CONSOLE /D _UNICODE /D
  UNICODE /Gm- /EHsc /RTC1 /MDd /GS /fp:precise /Zc:wchar_t /Zc:forScope /Zc:inline /permissive- /Fo"wifiExtr
  act\Debug\\" /Fd"wifiExtract\Debug\vc143.pdb" /external:W3 /Gd /TP /analyze- /FC /errorReport:queue wifiExt
  ract.cpp
  wifiExtract.cpp
Link:
  C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808\bin\HostX86\x86\link.exe
  /ERRORREPORT:QUEUE /OUT:"C:\Users\augur\source\repos\wifiExtract\wifiExtract\Debug\wifiExtract.exe" /INCREM
  ENTAL /ILK:"wifiExtract\Debug\wifiExtract.ilk" /NOLOGO kernel32.lib user32.lib gdi32.lib winspool.lib comdl
  g32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /MANIFEST /MANIFES
  TUAC:"level='asInvoker' uiAccess='false'" /manifest:embed /DEBUG /PDB:"C:\Users\augur\source\repos\wifiExtr
  act\wifiExtract\Debug\wifiExtract.pdb" /SUBSYSTEM:CONSOLE /TLBID:1 /DYNAMICBASE /NXCOMPAT /IMPLIB:"C:\Users
  \augur\source\repos\wifiExtract\wifiExtract\Debug\wifiExtract.lib" /MACHINE:X86 wifiExtract\Debug\wifiExtra
  ct.obj
  wifiExtract.vcxproj -> C:\Users\augur\source\repos\wifiExtract\wifiExtract\Debug\wifiExtract.exe
FinalizeBuildStatus:
  Deleting file "wifiExtract\Debug\wifiExtract.tlog\unsuccessfulbuild".
  Touching "wifiExtract\Debug\wifiExtract.tlog\wifiExtract.lastbuildstate".
Done Building Project "C:\Users\augur\source\repos\wifiExtract\wifiExtract\wifiExtract.vcxproj" (default targ
ets).


Build succeeded.
    0 Warning(s)
    0 Error(s)

Time Elapsed 00:00:06.61
```

```text
>wifiExtract.exe
[+] Found Wifi Profile:
[+] SSID: openNet
[+] No key material found

[+] Found Wifi Profile:
[+] SSID: networked
[+] Key: password123

```

[wifiExtract](https://github.com/hexagr/wifiExtract) on GitHub.

[^1]: https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanenuminterfaces
[^2]: https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlangetprofile







