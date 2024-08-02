# Windows 11 Virtualization Based Security
Fighting VBS with UEFI-lock to get 3rd party hypervisor running on host (VMware Workstation)

## Links
https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/

https://github.com/HotCakeX/Harden-Windows-Security/wiki/Device-Guard-and-Virtualization-Based-Security-in-Windows

## Intro
Credential Guard prevents credential theft attacks by protecting NTLM password hashes, Kerberos Ticket Granting Tickets (TGTs), and credentials stored by applications as domain credentials.

Credential Guard uses **Virtualization-based security (VBS)** to isolate secrets so that only privileged system software can access them. Unauthorized access to these secrets can lead to credential theft attacks like pass the hash and pass the ticket.

**Starting in Windows 11, 22H2 a VBS and Credential Guard are enabled by default on devices that meet the requirements.**

The default enablement is without UEFI Lock, thus allowing administrators to disable Credential Guard remotely if needed.

When Credential Guard is enabled, VBS is automatically enabled too.

Devices running Windows 11 Pro/Pro Edu 22H2 or later may have Virtualization-based Security (VBS) and/or Credential Guard automatically enabled if they meet the other requirements for default enablement, and have previously run Credential Guard. For example if Credential Guard was enabled on an Enterprise device that later downgraded to Pro.

To determine whether the Pro device is in this state, check if the following registry key exists: `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\IsolatedCredentialsRootSecret`

## Disable Credential Guard with UEFI Lock
set the following keys to REG_DWORD 0:
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags
```
run in admin cmd:
```
mountvol X: /s
copy %WINDIR%\System32\SecConfig.efi X:\EFI\Microsoft\Boot\SecConfig.efi /Y
bcdedit /create {0cb3b571-2f2e-4343-a879-d86a476d7215} /d "DebugTool" /application osloader
bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} path "\EFI\Microsoft\Boot\SecConfig.efi"
bcdedit /set {bootmgr} bootsequence {0cb3b571-2f2e-4343-a879-d86a476d7215}
bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} loadoptions DISABLE-LSA-ISO
bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} device partition=X:
mountvol X: /d
```

## Disabale Virtualization-based Security
delete the following keys:
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\RequirePlatformSecurityFeatures
```
run in admin cmd:
```
bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} loadoptions DISABLE-LSA-ISO,DISABLE-VBS
bcdedit /set vsmlaunchtype off
```

# Summary
Running in admin cmd (modifies command):
```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /t REG_DWORD /d 0x00000000 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "LsaCfgFlags" /t REG_DWORD /d 0x00000000 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0x00000000 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 0x00000000 /f

mountvol X: /s
copy %WINDIR%\System32\SecConfig.efi X:\EFI\Microsoft\Boot\SecConfig.efi /Y
bcdedit /create {0cb3b571-2f2e-4343-a879-d86a476d7215} /d "DebugTool" /application osloader
bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} path "\EFI\Microsoft\Boot\SecConfig.efi"
bcdedit /set {bootmgr} bootsequence {0cb3b571-2f2e-4343-a879-d86a476d7215}
bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} loadoptions DISABLE-LSA-ISO,DISABLE-VBS
bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} device partition=X:
bcdedit /set vsmlaunchtype off
mountvol X: /d
```

Reboot with precence control (press F3 twice when asked) ; VBS turned off
