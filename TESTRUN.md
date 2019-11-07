# Test Run

Documented below are the results from a test run.

<!-- TOC -->

- [Test Run](#test-run)
  - [Commands Executed](#commands-executed)
- [Test Run Results](#test-run-results)
  - [Inspec before Hardening](#inspec-before-hardening)
  - [Performing Hardening with `chef-apply`](#performing-hardening-with-chef-apply)
  - [Inspec after Hardening](#inspec-after-hardening)

<!-- /TOC -->

## Commands Executed

```batch
REM verify the status before hardening
inspec exec test\integration\default\default_spec.rb

REM perform hardening
REM note: although all recipes have been run in the below example, not everything is suitable and should be run with consideration in actual situations
cd recipes
for /f "usebackq tokens=* delims=" %i in (`dir /b`) do chef-apply "%i"
chef-apply "ciphers.rb"
chef-apply "core_hardening.rb"
chef-apply "deleteautologon.rb"
chef-apply "enable_firewall.rb"
chef-apply "enable_winrm.rb"
chef-apply "harden_ntlm.rb"
chef-apply "harden_winrm.rb"
chef-apply "schedule_task_update.rb"
chef-apply "windowsupdate.rb"
cd ..

REM verify the status before hardening
inspec exec test\integration\default\default_spec.rb
```

Note: Besides `chef-apply schedule_task_update.rb` which was unsuccessful due to some possible credentials issue, all other commands were run successfully.

# Test Run Results

## Inspec before Hardening

```batch
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\temp\windows_hardening>REM verify the status before hardening

C:\temp\windows_hardening>inspec exec test\integration\default\default_spec.rb

Profile: tests from test\integration\default\default_spec.rb (tests from test.integration.default.default_spec.rb)
Version: (not specified)
Target:  local://

  Registry Key HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
     [FAIL]  PasswordExpiryWarning should eq 14

     expected: 14
          got: 5

     (compared using ==)

     [FAIL]  ScreenSaverGracePeriod should eq "5"

     expected: "5"
          got: nil

     (compared using ==)

     [FAIL]  AllocateDASD should eq "0"

     expected: "0"
          got: nil

     (compared using ==)

     [FAIL]  ScRemoveOption should eq "1"

     expected: "1"
          got: "0"

     (compared using ==)

     [FAIL]  CachedLogonsCount should eq "4"

     expected: "4"
          got: "10"

     (compared using ==)

     [FAIL]  ForceUnlockLogon should eq 1

     expected: 1
          got: 0

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa
     [PASS]  FullPrivilegeAuditing should eq [0]
     [PASS]  AuditBaseObjects should eq 0
     [FAIL]  scenoapplylegacyauditpolicy should eq 1

     expected: 1
          got: nil

     (compared using ==)

     [FAIL]  DisableDomainCreds should eq 1

     expected: 1
          got: 0

     (compared using ==)

     [PASS]  LimitBlankPasswordUse should eq 1
     [PASS]  CrashOnAuditFail should eq 0
     [PASS]  RestrictAnonymousSAM should eq 1
     [FAIL]  RestrictAnonymous should eq 1

     expected: 1
          got: 0

     (compared using ==)

     [FAIL]  SubmitControl should eq 0

     expected: 0
          got: nil

     (compared using ==)

     [PASS]  ForceGuest should eq 0
     [PASS]  EveryoneIncludesAnonymous should eq 0
     [PASS]  NoLMHash should eq 1
     [FAIL]  SubmitControl should eq 0

     expected: 0
          got: nil

     (compared using ==)

     [FAIL]  LmCompatibilityLevel should eq 5

     expected: 5
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u
     [FAIL]  AllowOnlineID should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy
     [PASS]  Enabled should eq 0
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters
     [PASS]  MaximumPasswordAge should eq 30
     [PASS]  DisablePasswordChange should eq 0
     [FAIL]  RefusePasswordChange should eq 0

     expected: 0
          got: nil

     (compared using ==)

     [PASS]  SealSecureChannel should eq 1
     [PASS]  RequireSignOrSeal should eq 1
     [PASS]  SignSecureChannel should eq 1
     [PASS]  RequireStrongKey should eq 1
     [FAIL]  RestrictNTLMInDomain should eq 7

     expected: 7
          got: nil

     (compared using ==)

     [FAIL]  AuditNTLMInDomain should eq 7

     expected: 7
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters
     [FAIL]  DisableIPSourceRouting should eq 2

     expected: 2
          got: nil

     (compared using ==)

     [FAIL]  TcpMaxDataRetransmissions should eq 3

     expected: 3
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters
     [FAIL]  DisableIPSourceRouting should eq 2

     expected: 2
          got: nil

     (compared using ==)

     [FAIL]  TcpMaxDataRetransmissions should eq 3

     expected: 3
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
     [FAIL]  ProcessCreationIncludeCmdLine_Enabled should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters
     [FAIL]  supportedencryptiontypes should eq 2147483644

     expected: 2147483644
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
     [FAIL]  ConsentPromptBehaviorUser should eq 0

     expected: 0
          got: 3

     (compared using ==)

     [PASS]  EnableLUA should eq 1
     [PASS]  PromptOnSecureDesktop should eq 1
     [FAIL]  NoConnectedUser should eq 3

     expected: 3
          got: nil

     (compared using ==)

     [PASS]  EnableVirtualization should eq 1
     [PASS]  EnableUIADesktopToggle should eq 0
     [FAIL]  ConsentPromptBehaviorAdmin should eq 2

     expected: 2
          got: 5

     (compared using ==)

     [PASS]  EnableSecureUIAPaths should eq 1
     [FAIL]  FilterAdministratorToken should eq 1

     expected: 1
          got: 0

     (compared using ==)

     [FAIL]  MaxDevicePasswordFailedAttempts should eq 10

     expected: 10
          got: nil

     (compared using ==)

     [FAIL]  DontDisplayLastUserName should eq 1

     expected: 1
          got: 0

     (compared using ==)

     [FAIL]  DontDisplayLockedUserId should eq 3

     expected: 3
          got: nil

     (compared using ==)

     [FAIL]  InactivityTimeoutSecs should eq 900

     expected: 900
          got: nil

     (compared using ==)

     [PASS]  EnableInstallerDetection should eq 1
     [PASS]  DisableCAD should eq 0
     [PASS]  ShutdownWithoutLogon should eq 0
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters
     [FAIL]  enablesecuritysignature should eq 1

     expected: 1
          got: 0

     (compared using ==)

     [FAIL]  requiresecuritysignature should eq 1

     expected: 1
          got: 0

     (compared using ==)

     [PASS]  RestrictNullSessAccess should eq 1
     [PASS]  enableforcedlogoff should eq 1
     [PASS]  autodisconnect should eq 15
     [FAIL]  SMBServerNameHardeningLevel should eq 1

     expected: 1
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters
     [FAIL]  RequireSecuritySignature should eq 1

     expected: 1
          got: 0

     (compared using ==)

     [PASS]  EnableSecuritySignature should eq 1
     [PASS]  EnablePlainTextPassword should eq 0
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP
     [PASS]  LDAPClientIntegrity should eq 1
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS\Parameters
     [FAIL]  LDAPServerIntegrity should eq 2

     expected: 2
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager
     [PASS]  ProtectionMode should eq 1
     [FAIL]  SafeDllSearchMode should eq 1

     expected: 1
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\Defaults
     [FAIL]  IE should eq "*\\Internet Explorer\\iexplore.exe"

     expected: "*\\Internet Explorer\\iexplore.exe"
          got: nil

     (compared using ==)

     [FAIL]  7z should eq "*\\7-Zip\\7z.exe -EAF"

     expected: "*\\7-Zip\\7z.exe -EAF"
          got: nil

     (compared using ==)

     [FAIL]  7zFM should eq "*\\7-Zip\\7zFM.exe -EAF"

     expected: "*\\7-Zip\\7zFM.exe -EAF"
          got: nil

     (compared using ==)

     [FAIL]  7zGUI should eq "*\\7-Zip\\7zG.exe -EAF"

     expected: "*\\7-Zip\\7zG.exe -EAF"
          got: nil

     (compared using ==)

     [FAIL]  Access should eq "*\\OFFICE1*\\MSACCESS.EXE"

     expected: "*\\OFFICE1*\\MSACCESS.EXE"
          got: nil

     (compared using ==)

     [FAIL]  Acrobat should eq "*\\Adobe\\Acrobat*\\Acrobat\\Acrobat.exe"

     expected: "*\\Adobe\\Acrobat*\\Acrobat\\Acrobat.exe"
          got: nil

     (compared using ==)

     [FAIL]  AcrobatReader should eq "*\\Adobe\\Reader*\\Reader\\AcroRd32.exe"

     expected: "*\\Adobe\\Reader*\\Reader\\AcroRd32.exe"
          got: nil

     (compared using ==)

     [FAIL]  Chrome should eq "*\\Google\\Chrome\\Application\\chrome.exe -SEHOP"

     expected: "*\\Google\\Chrome\\Application\\chrome.exe -SEHOP"
          got: nil

     (compared using ==)

     [FAIL]  Excel should eq "*\\OFFICE1*\\EXCEL.EXE"

     expected: "*\\OFFICE1*\\EXCEL.EXE"
          got: nil

     (compared using ==)

     [FAIL]  Firefox should eq "*\\Mozilla Firefox\\firefox.exe"

     expected: "*\\Mozilla Firefox\\firefox.exe"
          got: nil

     (compared using ==)

     [FAIL]  FirefoxPluginContainer should eq "*\\Mozilla Firefox\\plugin-container.exe"

     expected: "*\\Mozilla Firefox\\plugin-container.exe"
          got: nil

     (compared using ==)

     [FAIL]  FoxitReader should eq "*\\Foxit Reader\\Foxit Reader.exe"

     expected: "*\\Foxit Reader\\Foxit Reader.exe"
          got: nil

     (compared using ==)

     [FAIL]  GoogleTalk should eq "*\\Google\\Google Talk\\googletalk.exe -DEP -SEHOP"

     expected: "*\\Google\\Google Talk\\googletalk.exe -DEP -SEHOP"
          got: nil

     (compared using ==)

     [FAIL]  InfoPath should eq "*\\OFFICE1*\\INFOPATH.EXE"

     expected: "*\\OFFICE1*\\INFOPATH.EXE"
          got: nil

     (compared using ==)

     [FAIL]  iTunes should eq "*\\iTunes\\iTunes.exe"

     expected: "*\\iTunes\\iTunes.exe"
          got: nil

     (compared using ==)

     [FAIL]  jre6_java should eq "*\\Java\\jre6\\bin\\java.exe -HeapSpray"

     expected: "*\\Java\\jre6\\bin\\java.exe -HeapSpray"
          got: nil

     (compared using ==)

     [FAIL]  jre6_javaw should eq "*\\Java\\jre6\\bin\\javaw.exe -HeapSpray"

     expected: "*\\Java\\jre6\\bin\\javaw.exe -HeapSpray"
          got: nil

     (compared using ==)

     [FAIL]  jre6_javaws should eq "*\\Java\\jre6\\bin\\javaws.exe -HeapSpray"

     expected: "*\\Java\\jre6\\bin\\javaws.exe -HeapSpray"
          got: nil

     (compared using ==)

     [FAIL]  jre7_java should eq "*\\Java\\jre7\\bin\\java.exe -HeapSpray"

     expected: "*\\Java\\jre7\\bin\\java.exe -HeapSpray"
          got: nil

     (compared using ==)

     [FAIL]  jre7_javaw should eq "*\\Java\\jre7\\bin\\javaw.exe -HeapSpray"

     expected: "*\\Java\\jre7\\bin\\javaw.exe -HeapSpray"
          got: nil

     (compared using ==)

     [FAIL]  jre7_javaws should eq "*\\Java\\jre7\\bin\\javaws.exe -HeapSpray"

     expected: "*\\Java\\jre7\\bin\\javaws.exe -HeapSpray"
          got: nil

     (compared using ==)

     [FAIL]  jre8_java should eq "*\\Java\\jre1.8*\\bin\\java.exe -HeapSpray"

     expected: "*\\Java\\jre1.8*\\bin\\java.exe -HeapSpray"
          got: nil

     (compared using ==)

     [FAIL]  jre8_javaw should eq "*\\Java\\jre1.8*\\bin\\javaw.exe -HeapSpray"

     expected: "*\\Java\\jre1.8*\\bin\\javaw.exe -HeapSpray"
          got: nil

     (compared using ==)

     [FAIL]  jre8_javaws should eq "*\\Java\\jre1.8*\\bin\\javaws.exe -HeapSpray"

     expected: "*\\Java\\jre1.8*\\bin\\javaws.exe -HeapSpray"
          got: nil

     (compared using ==)

     [FAIL]  LiveWriter should eq "*\\Windows Live\\Writer\\WindowsLiveWriter.exe"

     expected: "*\\Windows Live\\Writer\\WindowsLiveWriter.exe"
          got: nil

     (compared using ==)

     [FAIL]  Lync should eq "*\\OFFICE1*\\LYNC.EXE"

     expected: "*\\OFFICE1*\\LYNC.EXE"
          got: nil

     (compared using ==)

     [FAIL]  LyncCommunicator should eq "*\\Microsoft Lync\\communicator.exe"

     expected: "*\\Microsoft Lync\\communicator.exe"
          got: nil

     (compared using ==)

     [FAIL]  mIRC should eq "*\\mIRC\\mirc.exe"

     expected: "*\\mIRC\\mirc.exe"
          got: nil

     (compared using ==)

     [FAIL]  Opera should eq "*\\Opera\\opera.exe"

     expected: "*\\Opera\\opera.exe"
          got: nil

     (compared using ==)

     [FAIL]  Outlook should eq "*\\OFFICE1*\\OUTLOOK.EXE"

     expected: "*\\OFFICE1*\\OUTLOOK.EXE"
          got: nil

     (compared using ==)

     [FAIL]  PhotoGallery should eq "*\\Windows Live\\Photo Gallery\\WLXPhotoGallery.exe"

     expected: "*\\Windows Live\\Photo Gallery\\WLXPhotoGallery.exe"
          got: nil

     (compared using ==)

     [FAIL]  Photoshop should eq "*\\Adobe\\Adobe Photoshop CS*\\Photoshop.exe"

     expected: "*\\Adobe\\Adobe Photoshop CS*\\Photoshop.exe"
          got: nil

     (compared using ==)

     [FAIL]  Picture Manager should eq "*\\OFFICE1*\\OIS.EXE"

     expected: "*\\OFFICE1*\\OIS.EXE"
          got: nil

     (compared using ==)

     [FAIL]  Pidgin should eq "*\\Pidgin\\pidgin.exe"

     expected: "*\\Pidgin\\pidgin.exe"
          got: nil

     (compared using ==)

     [FAIL]  PowerPoint should eq "*\\OFFICE1*\\POWERPNT.EXE"

     expected: "*\\OFFICE1*\\POWERPNT.EXE"
          got: nil

     (compared using ==)

     [FAIL]  PPTViewer should eq "*\\OFFICE1*\\PPTVIEW.EXE"

     expected: "*\\OFFICE1*\\PPTVIEW.EXE"
          got: nil

     (compared using ==)

     [FAIL]  Publisher should eq "*\\OFFICE1*\\MSPUB.EXE"

     expected: "*\\OFFICE1*\\MSPUB.EXE"
          got: nil

     (compared using ==)

     [FAIL]  QuickTimePlayer should eq "*\\QuickTime\\QuickTimePlayer.exe"

     expected: "*\\QuickTime\\QuickTimePlayer.exe"
          got: nil

     (compared using ==)

     [FAIL]  RealConverter should eq "*\\Real\\RealPlayer\\realconverter.exe"

     expected: "*\\Real\\RealPlayer\\realconverter.exe"
          got: nil

     (compared using ==)

     [FAIL]  RealPlayer should eq "*\\Real\\RealPlayer\\realplay.exe"

     expected: "*\\Real\\RealPlayer\\realplay.exe"
          got: nil

     (compared using ==)

     [FAIL]  Safari should eq "*\\Safari\\Safari.exe"

     expected: "*\\Safari\\Safari.exe"
          got: nil

     (compared using ==)

     [FAIL]  SkyDrive should eq "*\\SkyDrive\\SkyDrive.exe"

     expected: "*\\SkyDrive\\SkyDrive.exe"
          got: nil

     (compared using ==)

     [FAIL]  Skype should eq "*\\Skype\\Phone\\Skype.exe -EAF"

     expected: "*\\Skype\\Phone\\Skype.exe -EAF"
          got: nil

     (compared using ==)

     [FAIL]  Thunderbird should eq "*\\Mozilla Thunderbird\\thunderbird.exe"

     expected: "*\\Mozilla Thunderbird\\thunderbird.exe"
          got: nil

     (compared using ==)

     [FAIL]  ThunderbirdPluginContainer should eq "*\\Mozilla Thunderbird\\plugin-container.exe"

     expected: "*\\Mozilla Thunderbird\\plugin-container.exe"
          got: nil

     (compared using ==)

     [FAIL]  UnRAR should eq "*\\WinRAR\\unrar.exe"

     expected: "*\\WinRAR\\unrar.exe"
          got: nil

     (compared using ==)

     [FAIL]  Visio should eq "*\\OFFICE1*\\VISIO.EXE"

     expected: "*\\OFFICE1*\\VISIO.EXE"
          got: nil

     (compared using ==)

     [FAIL]  VisioViewer should eq "*\\OFFICE1*\\VPREVIEW.EXE"

     expected: "*\\OFFICE1*\\VPREVIEW.EXE"
          got: nil

     (compared using ==)

     [FAIL]  VLC should eq "*\\VideoLAN\\VLC\\vlc.exe"

     expected: "*\\VideoLAN\\VLC\\vlc.exe"
          got: nil

     (compared using ==)

     [FAIL]  Winamp should eq "*\\Winamp\\winamp.exe"

     expected: "*\\Winamp\\winamp.exe"
          got: nil

     (compared using ==)

     [FAIL]  WindowsLiveMail should eq "*\\Windows Live\\Mail\\wlmail.exe"

     expected: "*\\Windows Live\\Mail\\wlmail.exe"
          got: nil

     (compared using ==)

     [FAIL]  WindowsMediaPlayer should eq "*\\Windows Media Player\\wmplayer.exe -SEHOP -EAF -MandatoryASLR"

     expected: "*\\Windows Media Player\\wmplayer.exe -SEHOP -EAF -MandatoryASLR"
          got: nil

     (compared using ==)

     [FAIL]  WinRARConsole should eq "*\\WinRAR\\rar.exe"

     expected: "*\\WinRAR\\rar.exe"
          got: nil

     (compared using ==)

     [FAIL]  WinRARGUI should eq "*\\WinRAR\\winrar.exe"

     expected: "*\\WinRAR\\winrar.exe"
          got: nil

     (compared using ==)

     [FAIL]  WinZip should eq "*\\WinZip\\winzip32.exe"

     expected: "*\\WinZip\\winzip32.exe"
          got: nil

     (compared using ==)

     [FAIL]  Winzip64 should eq "*\\WinZip\\winzip64.exe"

     expected: "*\\WinZip\\winzip64.exe"
          got: nil

     (compared using ==)

     [FAIL]  Word should eq "*\\OFFICE1*\\WINWORD.EXE"

     expected: "*\\OFFICE1*\\WINWORD.EXE"
          got: nil

     (compared using ==)

     [FAIL]  Wordpad should eq "*\\Windows NT\\Accessories\\wordpad.exe"

     expected: "*\\Windows NT\\Accessories\\wordpad.exe"
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\SysSettings
     [FAIL]  DEP should eq 2

     expected: 2
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel
     [PASS]  ObCaseInsensitive should eq 1
  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
     [FAIL]  UseLogonCredential should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management
     [FAIL]  ClearPageFileAtShutdown should eq 1

     expected: 1
          got: 0

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole
     [PASS]  setcommand should eq 0
     [PASS]  securitylevel should eq 0
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eventlog\Security
     [FAIL]  WarningLevel should eq 90

     expected: 90
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Cryptography
     [FAIL]  ForceKeyProtection should eq 2

     expected: 2
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers
     [PASS]  AddPrinterDrivers should eq 1
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers
     [PASS]  authenticodeenabled should eq 0
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths
     [PASS]  Machine should include /(System\\CurrentControlSet\\Control\\Print\\Printers)/
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths
     [PASS]  Machine should include /(System\\CurrentControlSet\\Control\\ProductOptions)/
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS
     [FAIL]  AllowRemoteShellAccess should eq 1

     expected: 1
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion
     [FAIL]  DisableContentFileUpdates should eq 1

     expected: 1
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows
     [FAIL]  CEIPEnable should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount
     [FAIL]  value should eq 0

     expected: 0
          got: 1

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsStore
     [FAIL]  AutoDownload should eq 4

     expected: 4
          got: nil

     (compared using ==)

     [FAIL]  DisableOSUpgrade should eq 1

     expected: 1
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System
     [FAIL]  DontDisplayNetworkSelectionUI should eq 1

     expected: 1
          got: nil

     (compared using ==)

     [FAIL]  DontEnumerateConnectedUsers should eq 1

     expected: 1
          got: nil

     (compared using ==)

     [FAIL]  EnumerateLocalUsers should eq 0

     expected: 0
          got: nil

     (compared using ==)

     [FAIL]  DisableLockScreenAppNotifications should eq 1

     expected: 1
          got: nil

     (compared using ==)

     [FAIL]  AllowDomainPINLogon should eq 0

     expected: 0
          got: nil

     (compared using ==)

     [FAIL]  EnableSmartScreen should eq 2

     expected: 2
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting
     [FAIL]  AutoApproveOSDumps should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent
     [FAIL]  DefaultConsent should eq 1

     expected: 1
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
     [FAIL]  AlwaysInstallElevated should eq 0

     expected: 0
          got: nil

     (compared using ==)

     [FAIL]  EnableUserControl should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SkyDrive
     [FAIL]  DisableFileSync should eq 1

     expected: 1
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application
     [FAIL]  MaxSize should eq 32768

     expected: 32768
          got: nil

     (compared using ==)

     [FAIL]  Retention should eq "0"

     expected: "0"
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security
     [FAIL]  MaxSize should eq 196608

     expected: 196608
          got: nil

     (compared using ==)

     [FAIL]  Retention should eq "0"

     expected: "0"
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System
     [FAIL]  MaxSize should eq 32768

     expected: 32768
          got: nil

     (compared using ==)

     [FAIL]  Retention should eq "0"

     expected: "0"
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup
     [FAIL]  MaxSize should eq 32768

     expected: 32768
          got: nil

     (compared using ==)

     [FAIL]  Retention should eq "0"

     expected: "0"
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
     [FAIL]  NoDriveTypeAutoRun should eq 255

     expected: 255
          got: nil

     (compared using ==)

     [FAIL]  NoPublishingWizard should eq 1

     expected: 1
          got: nil

     (compared using ==)

     [FAIL]  NoAutorun should eq 1

     expected: 1
          got: nil

     (compared using ==)

     [FAIL]  PreXPSP2ShellProtocolBehavior should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
     [FAIL]  MinEncryptionLevel should eq 3

     expected: 3
          got: nil

     (compared using ==)

     [FAIL]  fAllowUnsolicited should eq 0

     expected: 0
          got: nil

     (compared using ==)

     [FAIL]  DeleteTempDirsOnExit should eq 1

     expected: 1
          got: nil

     (compared using ==)

     [FAIL]  DisablePasswordSaving should eq 1

     expected: 1
          got: nil

     (compared using ==)

     [FAIL]  fPromptForPassword should eq 1

     expected: 1
          got: nil

     (compared using ==)

     [FAIL]  fAllowToGetHelp should eq 0

     expected: 0
          got: nil

     (compared using ==)

     [FAIL]  fDisableCdm should eq 1

     expected: 1
          got: nil

     (compared using ==)

     [FAIL]  fEncryptRPCTraffic should eq 1

     expected: 1
          got: nil

     (compared using ==)

     [FAIL]  PerSessionTempDir should eq 1

     expected: 1
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search
     [FAIL]  AllowIndexingEncryptedStoresOrItems should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization
     [FAIL]  NoLockScreenSlideshow should eq 1

     expected: 1
          got: nil

     (compared using ==)

     [FAIL]  NoLockScreenCamera should eq 1

     expected: 1
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Messenger\Client
     [FAIL]  CEIP should eq 2

     expected: 2
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DriverSearching
     [FAIL]  DontSearchWindowsUpdate should eq 1

     expected: 1
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
     [FAIL]  EnableScriptBlockLogging should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
     [FAIL]  EnableTranscripting should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI
     [FAIL]  DisablePasswordReveal should eq 1

     expected: 1
          got: nil

     (compared using ==)

     [FAIL]  EnumerateAdministrators should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters
     [FAIL]  nonamereleaseondemand should eq 1

     expected: 1
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections
     [FAIL]  NC_StdDomainUserSetLocation should eq 1

     expected: 1
          got: nil

     (compared using ==)

     [FAIL]  NC_AllowNetBridge_NLA should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths
     [FAIL]  \\*\NETLOGON should eq "RequireMutualAuthentication=1,RequireIntegrity=1"

     expected: "RequireMutualAuthentication=1,RequireIntegrity=1"
          got: nil

     (compared using ==)

     [FAIL]  \\*\SYSVOL should eq "RequireMutualAuthentication=1,RequireIntegrity=1"

     expected: "RequireMutualAuthentication=1,RequireIntegrity=1"
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy
     [FAIL]  fMinimizeConnections should eq 1

     expected: 1
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\TLS 1.0\Server
     [FAIL]  Enabled should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\TLS 1.1\Server
     [FAIL]  Enabled should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 3.0\Client
     [FAIL]  DisabledByDefault should eq 1

     expected: 1
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 3.0\Server
     [FAIL]  Enabled should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\PCT 1.0\Server
     [FAIL]  Enabled should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 2.0\Server
     [FAIL]  Enabled should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56
     [FAIL]  Enabled should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL
     [FAIL]  Enabled should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128
     [FAIL]  Enabled should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128
     [FAIL]  Enabled should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128
     [FAIL]  Enabled should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128
     [FAIL]  Enabled should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128
     [FAIL]  Enabled should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer
     [FAIL]  NoAutoplayfornonVolume should eq 1

     expected: 1
          got: nil

     (compared using ==)

     [FAIL]  NoDataExecutionPrevention should eq 0

     expected: 0
          got: nil

     (compared using ==)

     [FAIL]  NoHeapTerminationOnCorruption should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}
     [FAIL]  NoBackgroundPolicy should eq 0

     expected: 0
          got: nil

     (compared using ==)

     [FAIL]  NoGPOListChanges should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch
     [FAIL]  DriverLoadPolicy should eq 1

     expected: 1
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc
     [FAIL]  EnableAuthEpResolution should eq 1

     expected: 1
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds
     [FAIL]  DisableEnclosureDownload should eq 1

     expected: 1
          got: nil

     (compared using ==)

  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU
     [FAIL]  NoAutoRebootWithLoggedOnUsers should eq 0

     expected: 0
          got: nil

     (compared using ==)

  Powershell
     [FAIL]  stdout should eq "MinimumPasswordAge = 1\r\nMaximumPasswordAge = 42\r\nMinimumPasswordLength = 14\r\nPasswordComplexit...2-546\r\nSeDenyServiceLogonRight = *S-1-5-32-546\r\nSeDenyInteractiveLogonRight = *S-1-5-32-546\r\n"

     expected: "MinimumPasswordAge = 1\r\nMaximumPasswordAge = 42\r\nMinimumPasswordLength = 14\r\nPasswordComplexit...2-546\r\nSeDenyServiceLogonRight = *S-1-5-32-546\r\nSeDenyInteractiveLogonRight = *S-1-5-32-546\r\n"
          got: "MaximumPasswordAge = 42\r\nSeServiceLogonRight = *S-1-5-80-0\r\nSeInteractiveLogonRight = *S-1-5-32-...\nSeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-551\r\nSeTakeOwnershipPrivilege = *S-1-5-32-544\r\n"

     (compared using ==)

     Diff:




     @@ -1,23 +1,11 @@
     -MinimumPasswordAge = 1
      MaximumPasswordAge = 42
     -MinimumPasswordLength = 14
     -PasswordComplexity = 1
     -PasswordHistorySize = 24
     -LockoutBadCount = 10
     -ResetLockoutCount = 15
     -LockoutDuration = 15
     -SeNetworkLogonRight = *S-1-5-11,*S-1-5-32-544
      SeServiceLogonRight = *S-1-5-80-0
     -SeInteractiveLogonRight = *S-1-5-32-544
     +SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
      SeSecurityPrivilege = *S-1-5-32-544
      SeSystemEnvironmentPrivilege = *S-1-5-32-544
      SeProfileSingleProcessPrivilege = *S-1-5-32-544
      SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
     -SeRestorePrivilege = *S-1-5-32-544
     -SeShutdownPrivilege = *S-1-5-32-544
     +SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551
     +SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-551
      SeTakeOwnershipPrivilege = *S-1-5-32-544
     -SeDenyNetworkLogonRight = *S-1-5-32-546
     -SeDenyBatchLogonRight = *S-1-5-32-546
     -SeDenyServiceLogonRight = *S-1-5-32-546
     -SeDenyInteractiveLogonRight = *S-1-5-32-546

     [PASS]  stderr should eq ""

Test Summary: 38 successful, 175 failures, 0 skipped
```

## Performing Hardening with `chef-apply`

```batch
C:\temp\windows_hardening>cd recipes

C:\temp\windows_hardening>REM perform hardening

C:\temp\windows_hardening>REM note: although all recipes have been run in the below example, not everything is suitable and should be run with consideration in actual situations

C:\temp\windows_hardening\recipes>for /f "usebackq tokens=* delims=" %i in (`dir /b`) do chef-apply "%i"

C:\temp\windows_hardening\recipes>chef-apply "ciphers.rb"
Recipe: (chef-apply cookbook)::(chef-apply recipe)
  * registry_key[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\TLS 1.0\Server] action create
    - create key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\TLS 1.0\Server    - set value {:name=>"Enabled", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\TLS 1.1\Server] action create
    - create key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\TLS 1.1\Server    - set value {:name=>"Enabled", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\PCT 1.0\Server] action create
    - create key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\PCT 1.0\Server    - set value {:name=>"Enabled", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 2.0\Server] action create
    - create key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 2.0\Server    - set value {:name=>"Enabled", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 3.0\Client] action create
    - create key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 3.0\Client    - set value {:name=>"DisabledByDefault", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 3.0\Server] action create
    - create key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 3.0\Server    - set value {:name=>"Enabled", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56] action create
    - create key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56
    - set value {:name=>"Enabled", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL] action create
    - create key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL
    - set value {:name=>"Enabled", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128] action create
    - create key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128
    - set value {:name=>"Enabled", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128] action create
    - create key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128
    - set value {:name=>"Enabled", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128] action create
    - create key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128
    - set value {:name=>"Enabled", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128] action create
    - create key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128
    - set value {:name=>"Enabled", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128] action create
    - create key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128
    - set value {:name=>"Enabled", :type=>:dword, :data=>0}

C:\temp\windows_hardening\recipes>chef-apply "core_hardening.rb"
Recipe: (chef-apply cookbook)::(chef-apply recipe)
  * registry_key[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon] action create
    - set value {:name=>"PasswordExpiryWarning", :type=>:dword, :data=>14}
    - set value {:name=>"ScreenSaverGracePeriod", :type=>:string, :data=>5}
    - set value {:name=>"AllocateDASD", :type=>:string, :data=>0}
    - set value {:name=>"ScRemoveOption", :type=>:string, :data=>1}
    - set value {:name=>"ForceUnlockLogon", :type=>:dword, :data=>1}
    - set value {:name=>"AutoAdminLogon", :type=>:string, :data=>0}
    - set value {:name=>"CachedLogonsCount", :type=>:string, :data=>4}
  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa] action create
    - set value {:name=>"scenoapplylegacyauditpolicy", :type=>:dword, :data=>1}
    - set value {:name=>"DisableDomainCreds", :type=>:dword, :data=>1}
    - set value {:name=>"RestrictAnonymous", :type=>:dword, :data=>1}
    - set value {:name=>"SubmitControl", :type=>:dword, :data=>0}
    - set value {:name=>"SubmitControl", :type=>:dword, :data=>0}
    - set value {:name=>"LmCompatibilityLevel", :type=>:dword, :data=>5}
  * powershell_script[fullprivilegeauditing] action run
    - execute "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -InputFormat None -File "C:/Users/ADMINI~1/AppData/Local/Temp/2/chef-script20191107-1744-t71xf9.ps1"
  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u] action create
    - create key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u
    - set value {:name=>"AllowOnlineID", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy] action create (up to date)  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters] action create
    - set value {:name=>"RefusePasswordChange", :type=>:dword, :data=>0}
    - set value {:name=>"RestrictNTLMInDomain", :type=>:dword, :data=>7}
    - set value {:name=>"AuditNTLMInDomain", :type=>:dword, :data=>7}
  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters] action create
    - set value {:name=>"nonamereleaseondemand", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters] action create
    - set value {:name=>"DisableIPSourceRouting", :type=>:dword, :data=>2}
    - set value {:name=>"TcpMaxDataRetransmissions", :type=>:dword, :data=>3}
    - set value {:name=>"EnableICMPRedirect", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters] action create
    - set value {:name=>"DisableIPSourceRouting", :type=>:dword, :data=>2}
    - set value {:name=>"TcpMaxDataRetransmissions", :type=>:dword, :data=>3}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System] action create
    - set value {:name=>"ConsentPromptBehaviorUser", :type=>:dword, :data=>0}
    - set value {:name=>"LocalAccountTokenFilterPolicy", :type=>:dword, :data=>1}
    - set value {:name=>"MSAOptional", :type=>:dword, :data=>1}
    - set value {:name=>"NoConnectedUser", :type=>:dword, :data=>3}
    - set value {:name=>"ConsentPromptBehaviorAdmin", :type=>:dword, :data=>2}
    - set value {:name=>"FilterAdministratorToken", :type=>:dword, :data=>1}
    - set value {:name=>"MaxDevicePasswordFailedAttempts", :type=>:dword, :data=>10}
    - set value {:name=>"DontDisplayLastUserName", :type=>:dword, :data=>1}
    - set value {:name=>"DontDisplayLockedUserId", :type=>:dword, :data=>3}
    - set value {:name=>"InactivityTimeoutSecs", :type=>:dword, :data=>900}
    - set value {:name=>"legalnoticecaption", :type=>:string, :data=>"Company Logon Warning"}
    - set value {:name=>"legalnoticetext", :type=>:string, :data=>"Warning text goes here..."}
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters] action create
    - create key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters
    - set value {:name=>"supportedencryptiontypes", :type=>:dword, :data=>2147483644}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit] action create
    - set value {:name=>"ProcessCreationIncludeCmdLine_Enabled", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters] action create
    - set value {:name=>"enablesecuritysignature", :type=>:dword, :data=>1}
    - set value {:name=>"requiresecuritysignature", :type=>:dword, :data=>1}
    - set value {:name=>"SMBServerNameHardeningLevel", :type=>:dword, :data=>1}
  * powershell_script[nullsessions] action run
    - execute "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -InputFormat None -File "C:/Users/ADMINI~1/AppData/Local/Temp/2/chef-script20191107-1744-1r9wfm7.ps1"
  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters] action create
    - set value {:name=>"RequireSecuritySignature", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers] action create (up to date)
  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP] action create (up to date)
  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS\Parameters] action create
    - create key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS\Parameters
    - set value {:name=>"LDAPServerIntegrity", :type=>:dword, :data=>2}
  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager] action create
    - set value {:name=>"SafeDllSearchMode", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections] action create
    - set value {:name=>"NC_StdDomainUserSetLocation", :type=>:dword, :data=>1}
    - set value {:name=>"NC_AllowNetBridge_NLA", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\Defaults] action create
    - create key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\Defaults
    - set value {:name=>"IE", :type=>:string, :data=>"*\\Internet Explorer\\iexplore.exe"}
    - set value {:name=>"7z", :type=>:string, :data=>"*\\7-Zip\\7z.exe -EAF"}
    - set value {:name=>"7zFM", :type=>:string, :data=>"*\\7-Zip\\7zFM.exe -EAF"}
    - set value {:name=>"7zGUI", :type=>:string, :data=>"*\\7-Zip\\7zG.exe -EAF"}
    - set value {:name=>"Access", :type=>:string, :data=>"*\\OFFICE1*\\MSACCESS.EXE"}
    - set value {:name=>"Acrobat", :type=>:string, :data=>"*\\Adobe\\Acrobat*\\Acrobat\\Acrobat.exe"}
    - set value {:name=>"AcrobatReader", :type=>:string, :data=>"*\\Adobe\\Reader*\\Reader\\AcroRd32.exe"}
    - set value {:name=>"Chrome", :type=>:string, :data=>"*\\Google\\Chrome\\Application\\chrome.exe -SEHOP"}
    - set value {:name=>"Excel", :type=>:string, :data=>"*\\OFFICE1*\\EXCEL.EXE"}
    - set value {:name=>"Firefox", :type=>:string, :data=>"*\\Mozilla Firefox\\firefox.exe"}
    - set value {:name=>"FirefoxPluginContainer", :type=>:string, :data=>"*\\Mozilla Firefox\\plugin-container.exe"}
    - set value {:name=>"FoxitReader", :type=>:string, :data=>"*\\Foxit Reader\\Foxit Reader.exe"}
    - set value {:name=>"GoogleTalk", :type=>:string, :data=>"*\\Google\\Google Talk\\googletalk.exe -DEP -SEHOP"}
    - set value {:name=>"InfoPath", :type=>:string, :data=>"*\\OFFICE1*\\INFOPATH.EXE"}
    - set value {:name=>"iTunes", :type=>:string, :data=>"*\\iTunes\\iTunes.exe"}
    - set value {:name=>"jre6_java", :type=>:string, :data=>"*\\Java\\jre6\\bin\\java.exe -HeapSpray"}
    - set value {:name=>"jre6_javaw", :type=>:string, :data=>"*\\Java\\jre6\\bin\\javaw.exe -HeapSpray"}
    - set value {:name=>"jre6_javaws", :type=>:string, :data=>"*\\Java\\jre6\\bin\\javaws.exe -HeapSpray"}
    - set value {:name=>"jre7_java", :type=>:string, :data=>"*\\Java\\jre7\\bin\\java.exe -HeapSpray"}
    - set value {:name=>"jre7_javaw", :type=>:string, :data=>"*\\Java\\jre7\\bin\\javaw.exe -HeapSpray"}
    - set value {:name=>"jre7_javaws", :type=>:string, :data=>"*\\Java\\jre7\\bin\\javaws.exe -HeapSpray"}
    - set value {:name=>"jre8_java", :type=>:string, :data=>"*\\Java\\jre1.8*\\bin\\java.exe -HeapSpray"}
    - set value {:name=>"jre8_javaw", :type=>:string, :data=>"*\\Java\\jre1.8*\\bin\\javaw.exe -HeapSpray"}
    - set value {:name=>"jre8_javaws", :type=>:string, :data=>"*\\Java\\jre1.8*\\bin\\javaws.exe -HeapSpray"}
    - set value {:name=>"LiveWriter", :type=>:string, :data=>"*\\Windows Live\\Writer\\WindowsLiveWriter.exe"}
    - set value {:name=>"Lync", :type=>:string, :data=>"*\\OFFICE1*\\LYNC.EXE"}
    - set value {:name=>"LyncCommunicator", :type=>:string, :data=>"*\\Microsoft Lync\\communicator.exe"}
    - set value {:name=>"mIRC", :type=>:string, :data=>"*\\mIRC\\mirc.exe"}
    - set value {:name=>"Opera", :type=>:string, :data=>"*\\Opera\\opera.exe"}
    - set value {:name=>"Outlook", :type=>:string, :data=>"*\\OFFICE1*\\OUTLOOK.EXE"}
    - set value {:name=>"PhotoGallery", :type=>:string, :data=>"*\\Windows Live\\Photo Gallery\\WLXPhotoGallery.exe"}
    - set value {:name=>"Photoshop", :type=>:string, :data=>"*\\Adobe\\Adobe Photoshop CS*\\Photoshop.exe"}
    - set value {:name=>"Picture Manager", :type=>:string, :data=>"*\\OFFICE1*\\OIS.EXE"}
    - set value {:name=>"Pidgin", :type=>:string, :data=>"*\\Pidgin\\pidgin.exe"}
    - set value {:name=>"PowerPoint", :type=>:string, :data=>"*\\OFFICE1*\\POWERPNT.EXE"}
    - set value {:name=>"PPTViewer", :type=>:string, :data=>"*\\OFFICE1*\\PPTVIEW.EXE"}
    - set value {:name=>"Publisher", :type=>:string, :data=>"*\\OFFICE1*\\MSPUB.EXE"}
    - set value {:name=>"QuickTimePlayer", :type=>:string, :data=>"*\\QuickTime\\QuickTimePlayer.exe"}
    - set value {:name=>"RealConverter", :type=>:string, :data=>"*\\Real\\RealPlayer\\realconverter.exe"}
    - set value {:name=>"RealPlayer", :type=>:string, :data=>"*\\Real\\RealPlayer\\realplay.exe"}
    - set value {:name=>"Safari", :type=>:string, :data=>"*\\Safari\\Safari.exe"}
    - set value {:name=>"SkyDrive", :type=>:string, :data=>"*\\SkyDrive\\SkyDrive.exe"}
    - set value {:name=>"Skype", :type=>:string, :data=>"*\\Skype\\Phone\\Skype.exe -EAF"}
    - set value {:name=>"Thunderbird", :type=>:string, :data=>"*\\Mozilla Thunderbird\\thunderbird.exe"}
    - set value {:name=>"ThunderbirdPluginContainer", :type=>:string, :data=>"*\\Mozilla Thunderbird\\plugin-container.exe"}
    - set value {:name=>"UnRAR", :type=>:string, :data=>"*\\WinRAR\\unrar.exe"}
    - set value {:name=>"Visio", :type=>:string, :data=>"*\\OFFICE1*\\VISIO.EXE"}
    - set value {:name=>"VisioViewer", :type=>:string, :data=>"*\\OFFICE1*\\VPREVIEW.EXE"}
    - set value {:name=>"VLC", :type=>:string, :data=>"*\\VideoLAN\\VLC\\vlc.exe"}
    - set value {:name=>"Winamp", :type=>:string, :data=>"*\\Winamp\\winamp.exe"}
    - set value {:name=>"WindowsLiveMail", :type=>:string, :data=>"*\\Windows Live\\Mail\\wlmail.exe"}
    - set value {:name=>"WindowsMediaPlayer", :type=>:string, :data=>"*\\Windows Media Player\\wmplayer.exe -SEHOP -EAF -MandatoryASLR"}
    - set value {:name=>"WinRARConsole", :type=>:string, :data=>"*\\WinRAR\\rar.exe"}
    - set value {:name=>"WinRARGUI", :type=>:string, :data=>"*\\WinRAR\\winrar.exe"}
    - set value {:name=>"WinZip", :type=>:string, :data=>"*\\WinZip\\winzip32.exe"}
    - set value {:name=>"Winzip64", :type=>:string, :data=>"*\\WinZip\\winzip64.exe"}
    - set value {:name=>"Word", :type=>:string, :data=>"*\\OFFICE1*\\WINWORD.EXE"}
    - set value {:name=>"Wordpad", :type=>:string, :data=>"*\\Windows NT\\Accessories\\wordpad.exe"}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\SysSettings] action create
    - create key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\SysSettings
    - set value {:name=>"DEP", :type=>:dword, :data=>2}
  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel] action create (up to date)
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds] action create
    - create key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds
    - set value {:name=>"DisableEnclosureDownload", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest] action create
    - set value {:name=>"UseLogonCredential", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management] action create
    - set value {:name=>"ClearPageFileAtShutdown", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole] action create (up to date)
  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eventlog\Security] action create
    - set value {:name=>"WarningLevel", :type=>:dword, :data=>90}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Cryptography] action create
    - set value {:name=>"ForceKeyProtection", :type=>:dword, :data=>2}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers] action create (up to date)
  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths] action create (up to date)
  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths] action create (up to date)
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths] action create
    - set value {:name=>"\\\\*\\NETLOGON", :type=>:string, :data=>"RequireMutualAuthentication=1,RequireIntegrity=1"}
    - set value {:name=>"\\\\*\\SYSVOL", :type=>:string, :data=>"RequireMutualAuthentication=1,RequireIntegrity=1"}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy] action create
    - create key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy
    - set value {:name=>"fMinimizeConnections", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS] action create
    - create key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS
    - set value {:name=>"AllowRemoteShellAccess", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion] action create
    - create key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion
    - set value {:name=>"DisableContentFileUpdates", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows] action create
    - create key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows
    - set value {:name=>"CEIPEnable", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount] action create
    - set value {:name=>"value", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsStore] action create
    - create key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsStore
    - set value {:name=>"AutoDownload", :type=>:dword, :data=>4}
    - set value {:name=>"DisableOSUpgrade", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System] action create
    - set value {:name=>"DontDisplayNetworkSelectionUI", :type=>:dword, :data=>1}
    - set value {:name=>"DontEnumerateConnectedUsers", :type=>:dword, :data=>1}
    - set value {:name=>"EnumerateLocalUsers", :type=>:dword, :data=>0}
    - set value {:name=>"DisableLockScreenAppNotifications", :type=>:dword, :data=>1}
    - set value {:name=>"AllowDomainPINLogon", :type=>:dword, :data=>0}
    - set value {:name=>"EnableSmartScreen", :type=>:dword, :data=>2}
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting] action create
    - create key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting
    - set value {:name=>"AutoApproveOSDumps", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent] action create
    - create key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent
    - set value {:name=>"DefaultConsent", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer] action create
    - create key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
    - set value {:name=>"AlwaysInstallElevated", :type=>:dword, :data=>0}
    - set value {:name=>"EnableUserControl", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application] action create
    - create key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application
    - set value {:name=>"MaxSize", :type=>:dword, :data=>32768}
    - set value {:name=>"Retention", :type=>:string, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security] action create
    - create key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security
    - set value {:name=>"MaxSize", :type=>:dword, :data=>196608}
    - set value {:name=>"Retention", :type=>:string, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System] action create
    - create key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System
    - set value {:name=>"MaxSize", :type=>:dword, :data=>32768}
    - set value {:name=>"Retention", :type=>:string, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup] action create
    - create key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup
    - set value {:name=>"MaxSize", :type=>:dword, :data=>32768}
    - set value {:name=>"Retention", :type=>:string, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer] action create
    - set value {:name=>"NoDriveTypeAutoRun", :type=>:dword, :data=>255}
    - set value {:name=>"NoPublishingWizard", :type=>:dword, :data=>1}
    - set value {:name=>"NoAutorun", :type=>:dword, :data=>1}
    - set value {:name=>"PreXPSP2ShellProtocolBehavior", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer] action create
    - create key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer
    - set value {:name=>"NoAutoplayfornonVolume", :type=>:dword, :data=>1}
    - set value {:name=>"NoDataExecutionPrevention", :type=>:dword, :data=>0}
    - set value {:name=>"NoHeapTerminationOnCorruption", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}] action create
    - create key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}
    - set value {:name=>"NoBackgroundPolicy", :type=>:dword, :data=>0}
    - set value {:name=>"NoGPOListChanges", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search] action create
    - create key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search
    - set value {:name=>"AllowIndexingEncryptedStoresOrItems", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization] action create
    - create key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization
    - set value {:name=>"NoLockScreenSlideshow", :type=>:dword, :data=>1}
    - set value {:name=>"NoLockScreenCamera", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Messenger\Client] action create
    - create key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Messenger\Client
    - set value {:name=>"CEIP", :type=>:dword, :data=>2}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DriverSearching] action create
    - create key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DriverSearching
    - set value {:name=>"DontSearchWindowsUpdate", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging] action create
    - create key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
    - set value {:name=>"EnableScriptBlockLogging", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription] action create
    - create key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
    - set value {:name=>"EnableTranscripting", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI] action create
    - create key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI
    - set value {:name=>"DisablePasswordReveal", :type=>:dword, :data=>1}
    - set value {:name=>"EnumerateAdministrators", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SkyDrive] action create
    - create key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SkyDrive
    - set value {:name=>"DisableFileSync", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch] action create
    - create key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch
    - set value {:name=>"DriverLoadPolicy", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc] action create
    - create key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc
    - set value {:name=>"EnableAuthEpResolution", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU] action create
    - set value {:name=>"NoAutoRebootWithLoggedOnUsers", :type=>:dword, :data=>0}
  * powershell_script[import] action run
    - execute "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -InputFormat None -File "C:/Users/ADMINI~1/AppData/Local/Temp/2/chef-script20191107-1744-4ldbtm.ps1"
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services] action create
    - set value {:name=>"MinEncryptionLevel", :type=>:dword, :data=>3}
    - set value {:name=>"fAllowUnsolicited", :type=>:dword, :data=>0}
    - set value {:name=>"fPromptForPassword", :type=>:dword, :data=>1}
    - set value {:name=>"DeleteTempDirsOnExit", :type=>:dword, :data=>1}
    - set value {:name=>"DisablePasswordSaving", :type=>:dword, :data=>1}
    - set value {:name=>"fAllowToGetHelp", :type=>:dword, :data=>0}
    - set value {:name=>"fDisableCdm", :type=>:dword, :data=>1}
    - set value {:name=>"fEncryptRPCTraffic", :type=>:dword, :data=>1}
    - set value {:name=>"PerSessionTempDir", :type=>:dword, :data=>1}

C:\temp\windows_hardening\recipes>chef-apply "deleteautologon.rb"
Recipe: (chef-apply cookbook)::(chef-apply recipe)
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon] action create (up to date)
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon] action delete (up to date)
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon] action delete (up to date)

C:\temp\windows_hardening\recipes>chef-apply "enable_firewall.rb"
Recipe: (chef-apply cookbook)::(chef-apply recipe)
  * powershell_script[firewall] action run
    - execute "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -InputFormat None -File "C:/Users/ADMINI~1/AppData/Local/Temp/2/chef-script20191107-1268-169fkqr.ps1"
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile] action create
    - create key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile
    - set value {:name=>"DisableNotifications", :type=>:dword, :data=>1}
    - set value {:name=>"AllowLocalPolicyMerge", :type=>:dword, :data=>1}
    - set value {:name=>"AllowLocalIPsecPolicyMerge", :type=>:dword, :data=>1}
    - set value {:name=>"EnableFirewall", :type=>:dword, :data=>1}
    - set value {:name=>"DefaultOutboundAction", :type=>:dword, :data=>0}
    - set value {:name=>"DefaultInboundAction", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging] action create
    - create key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging
    - set value {:name=>"LogFilePath", :type=>:string, :data=>"%systemroot%\\system32\\logfiles\\firewall\\domainfw.log"}
    - set value {:name=>"LogFileSize", :type=>:dword, :data=>16384}
    - set value {:name=>"LogDroppedPackets", :type=>:dword, :data=>1}
    - set value {:name=>"LogSuccessfulConnections", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile] action create
    - create key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile
    - set value {:name=>"DisableNotifications", :type=>:dword, :data=>1}
    - set value {:name=>"AllowLocalPolicyMerge", :type=>:dword, :data=>1}
    - set value {:name=>"AllowLocalIPsecPolicyMerge", :type=>:dword, :data=>1}
    - set value {:name=>"EnableFirewall", :type=>:dword, :data=>1}
    - set value {:name=>"DefaultOutboundAction", :type=>:dword, :data=>0}
    - set value {:name=>"DefaultInboundAction", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging] action create
    - create key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging
    - set value {:name=>"LogFilePath", :type=>:string, :data=>"%systemroot%\\system32\\logfiles\\firewall\\privatefw.log"}
    - set value {:name=>"LogFileSize", :type=>:dword, :data=>16384}
    - set value {:name=>"LogDroppedPackets", :type=>:dword, :data=>1}
    - set value {:name=>"LogSuccessfulConnections", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile] action create
    - create key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile
    - set value {:name=>"DisableNotifications", :type=>:dword, :data=>0}
    - set value {:name=>"AllowLocalPolicyMerge", :type=>:dword, :data=>1}
    - set value {:name=>"AllowLocalIPsecPolicyMerge", :type=>:dword, :data=>1}
    - set value {:name=>"EnableFirewall", :type=>:dword, :data=>1}
    - set value {:name=>"DefaultOutboundAction", :type=>:dword, :data=>0}
    - set value {:name=>"DefaultInboundAction", :type=>:dword, :data=>1}
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging] action create
    - create key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging
    - set value {:name=>"LogFilePath", :type=>:string, :data=>"%systemroot%\\system32\\logfiles\\firewall\\publicfw.log"}
    - set value {:name=>"LogFileSize", :type=>:dword, :data=>16384}
    - set value {:name=>"LogDroppedPackets", :type=>:dword, :data=>1}
    - set value {:name=>"LogSuccessfulConnections", :type=>:dword, :data=>1}

C:\temp\windows_hardening\recipes>chef-apply "enable_winrm.rb"
Recipe: (chef-apply cookbook)::(chef-apply recipe)
  * powershell_script[enableWinRM] action run
    - execute "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -InputFormat None -File "C:/Users/ADMINI~1/AppData/Local/Temp/2/chef-script20191107-3688-lblqss.ps1"

C:\temp\windows_hardening\recipes>chef-apply "harden_ntlm.rb"
Recipe: (chef-apply cookbook)::(chef-apply recipe)
  * registry_key[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0] action create
    - set value {:name=>"RestrictReceivingNTLMTraffic", :type=>:dword, :data=>2}
    - set value {:name=>"RestrictSendingNTLMTraffic", :type=>:dword, :data=>2}
    - set value {:name=>"AuditReceivingNTLMTraffic", :type=>:dword, :data=>2}
    - set value {:name=>"allownullsessionfallback", :type=>:dword, :data=>0}
    - set value {:name=>"NTLMMinServerSec", :type=>:dword, :data=>537395200}
    - set value {:name=>"NTLMMinClientSec", :type=>:dword, :data=>537395200}

C:\temp\windows_hardening\recipes>chef-apply "harden_winrm.rb"
Recipe: (chef-apply cookbook)::(chef-apply recipe)
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service] action create
    - set value {:name=>"AllowAutoConfig", :type=>:dword, :data=>2}
    - set value {:name=>"IPv4Filter", :type=>:dword, :data=>2}
    - set value {:name=>"DisableRunAs", :type=>:dword, :data=>2}
    - set value {:name=>"AllowUnencryptedTraffic", :type=>:dword, :data=>0}
  * registry_key[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client] action create
    - create key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client
    - set value {:name=>"AllowDigest", :type=>:dword, :data=>1}
    - set value {:name=>"AllowBasic", :type=>:dword, :data=>0}
    - set value {:name=>"AllowUnencryptedTraffic", :type=>:dword, :data=>0}

C:\temp\windows_hardening\recipes>chef-apply "schedule_task_update.rb"
Recipe: (chef-apply cookbook)::(chef-apply recipe)
  * windows_task[windows_update] action create

    ================================================================================
    Error executing action `create` on resource 'windows_task[windows_update]'
    ================================================================================

    Win32::TaskScheduler::Error
    ---------------------------
    register_task_definition: No mapping between account names and security IDs was done.

    Resource Declaration:
    ---------------------
    # In schedule_task_update.rb

     16: windows_task 'windows_update' do
     17:   task_name 'WindowsUpdate'
     18:   user '_administrator'
     19:   password 'TechPassword12!'
     20:   force true
     21:   cwd 'C:\\temp\\windows_hardening\\files'
     22:   command 'windows_update.ps1'
     23:   run_level :highest
     24:   frequency :daily
     25:   start_time '03:00'
     26: end
     27:

    Compiled Resource:
    ------------------
    # Declared in schedule_task_update.rb:16:in `run_chef_recipe'

    windows_task("windows_update") do
      action [:create]
      default_guard_interpreter :default
      declared_type :windows_task
      cookbook_name "(chef-apply cookbook)"
      recipe_name "(chef-apply recipe)"
      task_name "WindowsUpdate"
      user "_administrator"
      password "TechPassword12!"
      force true
      cwd "C:\\temp\\windows_hardening\\files"
      command "windows_update.ps1"
      run_level :highest
      frequency :daily
      start_time "03:00"
      execution_time_limit 4320
      password_required true
      start_day "11/07/2019"
    end

    System Info:
    ------------
    chef_version=15.4.45
    platform=windows
    platform_version=10.0.14393
    ruby=ruby 2.6.5p114 (2019-10-01 revision 67812) [x64-mingw32]
    program_name=C:/opscode/chef-workstation/bin/chef-apply
    executable=C:/opscode/chef-workstation/bin/chef-apply

[2019-11-07T13:42:05-08:00] FATAL: Stacktrace dumped to C:/Users/Administrator/.chef/cache/chef-stacktrace.out
[2019-11-07T13:42:05-08:00] FATAL: Please provide the contents of the stacktrace.out file if you file a bug report
[2019-11-07T13:42:05-08:00] FATAL: Win32::TaskScheduler::Error: windows_task[windows_update] ((chef-apply cookbook)::(chef-apply recipe) line 16) had an error: Win32::TaskScheduler::Error: register_task_definition: No mapping between account names and security IDs was done.

C:\temp\windows_hardening\recipes>chef-apply "windowsupdate.rb"
Recipe: (chef-apply cookbook)::(chef-apply recipe)
  * registry_key[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU] action create
    - set value {:name=>"NoAutoUpdate", :type=>:dword, :data=>0}
    - set value {:name=>"AUOptions", :type=>:dword, :data=>4}
    - set value {:name=>"ScheduledInstallDay", :type=>:dword, :data=>0}
    - set value {:name=>"ScheduledInstallTime", :type=>:dword, :data=>3}
```

## Inspec after Hardening

```batch
C:\temp\windows_hardening\recipes>cd ..

C:\temp\windows_hardening>REM verify the status after hardening

C:\temp\windows_hardening>inspec exec test\integration\default\default_spec.rb

Profile: tests from test\integration\default\default_spec.rb (tests from test.integration.default.default_spec.rb)
Version: (not specified)
Target:  local://

  Registry Key HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
     [PASS]  PasswordExpiryWarning should eq 14
     [PASS]  ScreenSaverGracePeriod should eq "5"
     [PASS]  AllocateDASD should eq "0"
     [PASS]  ScRemoveOption should eq "1"
     [PASS]  CachedLogonsCount should eq "4"
     [PASS]  ForceUnlockLogon should eq 1
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa
     [PASS]  FullPrivilegeAuditing should eq [0]
     [PASS]  AuditBaseObjects should eq 0
     [PASS]  scenoapplylegacyauditpolicy should eq 1
     [PASS]  DisableDomainCreds should eq 1
     [PASS]  LimitBlankPasswordUse should eq 1
     [PASS]  CrashOnAuditFail should eq 0
     [PASS]  RestrictAnonymousSAM should eq 1
     [PASS]  RestrictAnonymous should eq 1
     [PASS]  SubmitControl should eq 0
     [PASS]  ForceGuest should eq 0
     [PASS]  EveryoneIncludesAnonymous should eq 0
     [PASS]  NoLMHash should eq 1
     [PASS]  SubmitControl should eq 0
     [PASS]  LmCompatibilityLevel should eq 5
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u
     [PASS]  AllowOnlineID should eq 0
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy
     [PASS]  Enabled should eq 0
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters
     [PASS]  MaximumPasswordAge should eq 30
     [PASS]  DisablePasswordChange should eq 0
     [PASS]  RefusePasswordChange should eq 0
     [PASS]  SealSecureChannel should eq 1
     [PASS]  RequireSignOrSeal should eq 1
     [PASS]  SignSecureChannel should eq 1
     [PASS]  RequireStrongKey should eq 1
     [PASS]  RestrictNTLMInDomain should eq 7
     [PASS]  AuditNTLMInDomain should eq 7
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters
     [PASS]  DisableIPSourceRouting should eq 2
     [PASS]  TcpMaxDataRetransmissions should eq 3
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters
     [PASS]  DisableIPSourceRouting should eq 2
     [PASS]  TcpMaxDataRetransmissions should eq 3
  Registry Key HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
     [PASS]  ProcessCreationIncludeCmdLine_Enabled should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters
     [PASS]  supportedencryptiontypes should eq 2147483644
  Registry Key HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
     [PASS]  ConsentPromptBehaviorUser should eq 0
     [PASS]  EnableLUA should eq 1
     [PASS]  PromptOnSecureDesktop should eq 1
     [PASS]  NoConnectedUser should eq 3
     [PASS]  EnableVirtualization should eq 1
     [PASS]  EnableUIADesktopToggle should eq 0
     [PASS]  ConsentPromptBehaviorAdmin should eq 2
     [PASS]  EnableSecureUIAPaths should eq 1
     [PASS]  FilterAdministratorToken should eq 1
     [PASS]  MaxDevicePasswordFailedAttempts should eq 10
     [PASS]  DontDisplayLastUserName should eq 1
     [PASS]  DontDisplayLockedUserId should eq 3
     [PASS]  InactivityTimeoutSecs should eq 900
     [PASS]  EnableInstallerDetection should eq 1
     [PASS]  DisableCAD should eq 0
     [PASS]  ShutdownWithoutLogon should eq 0
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters
     [PASS]  enablesecuritysignature should eq 1
     [PASS]  requiresecuritysignature should eq 1
     [PASS]  RestrictNullSessAccess should eq 1
     [PASS]  enableforcedlogoff should eq 1
     [PASS]  autodisconnect should eq 15
     [PASS]  SMBServerNameHardeningLevel should eq 1
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters
     [PASS]  RequireSecuritySignature should eq 1
     [PASS]  EnableSecuritySignature should eq 1
     [PASS]  EnablePlainTextPassword should eq 0
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP
     [PASS]  LDAPClientIntegrity should eq 1
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS\Parameters
     [PASS]  LDAPServerIntegrity should eq 2
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager
     [PASS]  ProtectionMode should eq 1
     [PASS]  SafeDllSearchMode should eq 1
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\Defaults
     [PASS]  IE should eq "*\\Internet Explorer\\iexplore.exe"
     [PASS]  7z should eq "*\\7-Zip\\7z.exe -EAF"
     [PASS]  7zFM should eq "*\\7-Zip\\7zFM.exe -EAF"
     [PASS]  7zGUI should eq "*\\7-Zip\\7zG.exe -EAF"
     [PASS]  Access should eq "*\\OFFICE1*\\MSACCESS.EXE"
     [PASS]  Acrobat should eq "*\\Adobe\\Acrobat*\\Acrobat\\Acrobat.exe"
     [PASS]  AcrobatReader should eq "*\\Adobe\\Reader*\\Reader\\AcroRd32.exe"
     [PASS]  Chrome should eq "*\\Google\\Chrome\\Application\\chrome.exe -SEHOP"
     [PASS]  Excel should eq "*\\OFFICE1*\\EXCEL.EXE"
     [PASS]  Firefox should eq "*\\Mozilla Firefox\\firefox.exe"
     [PASS]  FirefoxPluginContainer should eq "*\\Mozilla Firefox\\plugin-container.exe"
     [PASS]  FoxitReader should eq "*\\Foxit Reader\\Foxit Reader.exe"
     [PASS]  GoogleTalk should eq "*\\Google\\Google Talk\\googletalk.exe -DEP -SEHOP"
     [PASS]  InfoPath should eq "*\\OFFICE1*\\INFOPATH.EXE"
     [PASS]  iTunes should eq "*\\iTunes\\iTunes.exe"
     [PASS]  jre6_java should eq "*\\Java\\jre6\\bin\\java.exe -HeapSpray"
     [PASS]  jre6_javaw should eq "*\\Java\\jre6\\bin\\javaw.exe -HeapSpray"
     [PASS]  jre6_javaws should eq "*\\Java\\jre6\\bin\\javaws.exe -HeapSpray"
     [PASS]  jre7_java should eq "*\\Java\\jre7\\bin\\java.exe -HeapSpray"
     [PASS]  jre7_javaw should eq "*\\Java\\jre7\\bin\\javaw.exe -HeapSpray"
     [PASS]  jre7_javaws should eq "*\\Java\\jre7\\bin\\javaws.exe -HeapSpray"
     [PASS]  jre8_java should eq "*\\Java\\jre1.8*\\bin\\java.exe -HeapSpray"
     [PASS]  jre8_javaw should eq "*\\Java\\jre1.8*\\bin\\javaw.exe -HeapSpray"
     [PASS]  jre8_javaws should eq "*\\Java\\jre1.8*\\bin\\javaws.exe -HeapSpray"
     [PASS]  LiveWriter should eq "*\\Windows Live\\Writer\\WindowsLiveWriter.exe"
     [PASS]  Lync should eq "*\\OFFICE1*\\LYNC.EXE"
     [PASS]  LyncCommunicator should eq "*\\Microsoft Lync\\communicator.exe"
     [PASS]  mIRC should eq "*\\mIRC\\mirc.exe"
     [PASS]  Opera should eq "*\\Opera\\opera.exe"
     [PASS]  Outlook should eq "*\\OFFICE1*\\OUTLOOK.EXE"
     [PASS]  PhotoGallery should eq "*\\Windows Live\\Photo Gallery\\WLXPhotoGallery.exe"
     [PASS]  Photoshop should eq "*\\Adobe\\Adobe Photoshop CS*\\Photoshop.exe"
     [PASS]  Picture Manager should eq "*\\OFFICE1*\\OIS.EXE"
     [PASS]  Pidgin should eq "*\\Pidgin\\pidgin.exe"
     [PASS]  PowerPoint should eq "*\\OFFICE1*\\POWERPNT.EXE"
     [PASS]  PPTViewer should eq "*\\OFFICE1*\\PPTVIEW.EXE"
     [PASS]  Publisher should eq "*\\OFFICE1*\\MSPUB.EXE"
     [PASS]  QuickTimePlayer should eq "*\\QuickTime\\QuickTimePlayer.exe"
     [PASS]  RealConverter should eq "*\\Real\\RealPlayer\\realconverter.exe"
     [PASS]  RealPlayer should eq "*\\Real\\RealPlayer\\realplay.exe"
     [PASS]  Safari should eq "*\\Safari\\Safari.exe"
     [PASS]  SkyDrive should eq "*\\SkyDrive\\SkyDrive.exe"
     [PASS]  Skype should eq "*\\Skype\\Phone\\Skype.exe -EAF"
     [PASS]  Thunderbird should eq "*\\Mozilla Thunderbird\\thunderbird.exe"
     [PASS]  ThunderbirdPluginContainer should eq "*\\Mozilla Thunderbird\\plugin-container.exe"
     [PASS]  UnRAR should eq "*\\WinRAR\\unrar.exe"
     [PASS]  Visio should eq "*\\OFFICE1*\\VISIO.EXE"
     [PASS]  VisioViewer should eq "*\\OFFICE1*\\VPREVIEW.EXE"
     [PASS]  VLC should eq "*\\VideoLAN\\VLC\\vlc.exe"
     [PASS]  Winamp should eq "*\\Winamp\\winamp.exe"
     [PASS]  WindowsLiveMail should eq "*\\Windows Live\\Mail\\wlmail.exe"
     [PASS]  WindowsMediaPlayer should eq "*\\Windows Media Player\\wmplayer.exe -SEHOP -EAF -MandatoryASLR"
     [PASS]  WinRARConsole should eq "*\\WinRAR\\rar.exe"
     [PASS]  WinRARGUI should eq "*\\WinRAR\\winrar.exe"
     [PASS]  WinZip should eq "*\\WinZip\\winzip32.exe"
     [PASS]  Winzip64 should eq "*\\WinZip\\winzip64.exe"
     [PASS]  Word should eq "*\\OFFICE1*\\WINWORD.EXE"
     [PASS]  Wordpad should eq "*\\Windows NT\\Accessories\\wordpad.exe"
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\SysSettings
     [PASS]  DEP should eq 2
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel
     [PASS]  ObCaseInsensitive should eq 1
  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
     [PASS]  UseLogonCredential should eq 0
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management
     [PASS]  ClearPageFileAtShutdown should eq 1
  Registry Key HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole
     [PASS]  setcommand should eq 0
     [PASS]  securitylevel should eq 0
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eventlog\Security
     [PASS]  WarningLevel should eq 90
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Cryptography
     [PASS]  ForceKeyProtection should eq 2
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers
     [PASS]  AddPrinterDrivers should eq 1
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers
     [PASS]  authenticodeenabled should eq 0
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths
     [PASS]  Machine should include /(System\\CurrentControlSet\\Control\\Print\\Printers)/
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths
     [PASS]  Machine should include /(System\\CurrentControlSet\\Control\\ProductOptions)/
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS
     [PASS]  AllowRemoteShellAccess should eq 1
  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion
     [PASS]  DisableContentFileUpdates should eq 1
  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows
     [PASS]  CEIPEnable should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount
     [PASS]  value should eq 0
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsStore
     [PASS]  AutoDownload should eq 4
     [PASS]  DisableOSUpgrade should eq 1
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System
     [PASS]  DontDisplayNetworkSelectionUI should eq 1
     [PASS]  DontEnumerateConnectedUsers should eq 1
     [PASS]  EnumerateLocalUsers should eq 0
     [PASS]  DisableLockScreenAppNotifications should eq 1
     [PASS]  AllowDomainPINLogon should eq 0
     [PASS]  EnableSmartScreen should eq 2
  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting
     [PASS]  AutoApproveOSDumps should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent
     [PASS]  DefaultConsent should eq 1
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
     [PASS]  AlwaysInstallElevated should eq 0
     [PASS]  EnableUserControl should eq 0
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SkyDrive
     [PASS]  DisableFileSync should eq 1
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application
     [PASS]  MaxSize should eq 32768
     [PASS]  Retention should eq "0"
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security
     [PASS]  MaxSize should eq 196608
     [PASS]  Retention should eq "0"
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System
     [PASS]  MaxSize should eq 32768
     [PASS]  Retention should eq "0"
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup
     [PASS]  MaxSize should eq 32768
     [PASS]  Retention should eq "0"
  Registry Key HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
     [PASS]  NoDriveTypeAutoRun should eq 255
     [PASS]  NoPublishingWizard should eq 1
     [PASS]  NoAutorun should eq 1
     [PASS]  PreXPSP2ShellProtocolBehavior should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
     [PASS]  MinEncryptionLevel should eq 3
     [PASS]  fAllowUnsolicited should eq 0
     [PASS]  DeleteTempDirsOnExit should eq 1
     [PASS]  DisablePasswordSaving should eq 1
     [PASS]  fPromptForPassword should eq 1
     [PASS]  fAllowToGetHelp should eq 0
     [PASS]  fDisableCdm should eq 1
     [PASS]  fEncryptRPCTraffic should eq 1
     [PASS]  PerSessionTempDir should eq 1
  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search
     [PASS]  AllowIndexingEncryptedStoresOrItems should eq 0
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization
     [PASS]  NoLockScreenSlideshow should eq 1
     [PASS]  NoLockScreenCamera should eq 1
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Messenger\Client
     [PASS]  CEIP should eq 2
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DriverSearching
     [PASS]  DontSearchWindowsUpdate should eq 1
  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
     [PASS]  EnableScriptBlockLogging should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
     [PASS]  EnableTranscripting should eq 0
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI
     [PASS]  DisablePasswordReveal should eq 1
     [PASS]  EnumerateAdministrators should eq 0
  Registry Key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters
     [PASS]  nonamereleaseondemand should eq 1
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections
     [PASS]  NC_StdDomainUserSetLocation should eq 1
     [PASS]  NC_AllowNetBridge_NLA should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths
     [PASS]  \\*\NETLOGON should eq "RequireMutualAuthentication=1,RequireIntegrity=1"
     [PASS]  \\*\SYSVOL should eq "RequireMutualAuthentication=1,RequireIntegrity=1"
  Registry Key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy
     [PASS]  fMinimizeConnections should eq 1
  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\TLS 1.0\Server
     [PASS]  Enabled should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\TLS 1.1\Server
     [PASS]  Enabled should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 3.0\Client
     [PASS]  DisabledByDefault should eq 1
  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 3.0\Server
     [PASS]  Enabled should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\PCT 1.0\Server
     [PASS]  Enabled should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 2.0\Server
     [PASS]  Enabled should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56
     [PASS]  Enabled should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL
     [PASS]  Enabled should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128
     [PASS]  Enabled should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128
     [PASS]  Enabled should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128
     [PASS]  Enabled should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128
     [PASS]  Enabled should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128
     [PASS]  Enabled should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer
     [PASS]  NoAutoplayfornonVolume should eq 1
     [PASS]  NoDataExecutionPrevention should eq 0
     [PASS]  NoHeapTerminationOnCorruption should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}
     [PASS]  NoBackgroundPolicy should eq 0
     [PASS]  NoGPOListChanges should eq 0
  Registry Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch
     [PASS]  DriverLoadPolicy should eq 1
  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc
     [PASS]  EnableAuthEpResolution should eq 1
  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds
     [PASS]  DisableEnclosureDownload should eq 1
  Registry Key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU
     [PASS]  NoAutoRebootWithLoggedOnUsers should eq 0
  Powershell
     [PASS]  stdout should eq "MinimumPasswordAge = 1\r\nMaximumPasswordAge = 42\r\nMinimumPasswordLength = 14\r\nPasswordComplexit...2-546\r\nSeDenyServiceLogonRight = *S-1-5-32-546\r\nSeDenyInteractiveLogonRight = *S-1-5-32-546\r\n"
     [PASS]  stderr should eq ""

Test Summary: 213 successful, 0 failures, 0 skipped

C:\temp\windows_hardening>
```
