; Inno Setup Script for Multi-Guard Antivirus & Endpoint Security
; Developed by Multi-Servis (https://multi-servis.pl)

#define MyAppName "Multi-Guard"
#define MyAppVersion "1.1.8.2"
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

; Wykluczenia w rejestrze Microsoft Defender dla Multi-Guard (brak konfliktów i fałszywych alarmów)
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"; ValueType: dword; ValueName: "{app}"; ValueData: 0; Flags: uninsdeletevalue
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"; ValueType: dword; ValueName: "{commonappdata}\Multi-Guard"; ValueData: 0; Flags: uninsdeletevalue
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"; ValueType: dword; ValueName: "{#MyAppExeName}"; ValueData: 0; Flags: uninsdeletevalue
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"; ValueType: dword; ValueName: "{app}\{#MyAppExeName}"; ValueData: 0; Flags: uninsdeletevalue
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"; ValueType: dword; ValueName: ".mgvault"; ValueData: 0; Flags: uninsdeletevalue
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"; ValueType: dword; ValueName: ".mgenc"; ValueData: 0; Flags: uninsdeletevalue

; Wyciszenie powiadomień Microsoft Defender (powiadomienia i alerty tylko z Multi-Guard)
Root: HKLM; Subkey: "SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"; ValueType: dword; ValueName: "DisableEnhancedNotifications"; ValueData: 1; Flags: uninsdeletevalue
Root: HKLM; Subkey: "SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications"; ValueType: dword; ValueName: "DisableNotifications"; ValueData: 1; Flags: uninsdeletevalue
Root: HKLM; Subkey: "SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications"; ValueType: dword; ValueName: "DisableEnhancedNotifications"; ValueData: 1; Flags: uninsdeletevalue

; Ukrycie ikony Windows Security Health Systray (zasobnik systemowy przejmuje Multi-Guard)
Root: HKLM; Subkey: "SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray"; ValueType: dword; ValueName: "HideSystray"; ValueData: 1; Flags: uninsdeletevalue

[Dirs]
Name: "{app}"
Name: "{commonappdata}\Multi-Guard"; Permissions: users-modify

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "--tray"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

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

    // Rejestracja rozszerzenia Multi-Guard WebShield w przeglądarkach Chrome i Edge
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Google\Chrome\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Google\Chrome\Extensions\multiguard_webshield', 'version', '1.2.0');
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Google\Chrome\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Google\Chrome\Extensions\multiguard_webshield', 'version', '1.2.0');

    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Edge\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Edge\Extensions\multiguard_webshield', 'version', '1.2.0');
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Microsoft\Edge\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Microsoft\Edge\Extensions\multiguard_webshield', 'version', '1.2.0');

    // Wywołanie komend PowerShell dla natychmiastowego zastosowania wykluczeń i wyciszenia Defender
    Exec('powershell.exe', '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' +
         'Add-MpPreference -ExclusionPath ''' + ExpandConstant('{app}') + ''' -ErrorAction SilentlyContinue; ' +
         'Add-MpPreference -ExclusionPath ''' + ExpandConstant('{commonappdata}\Multi-Guard') + ''' -ErrorAction SilentlyContinue; ' +
         'Add-MpPreference -ExclusionProcess ''Multi-Guard.exe'' -ErrorAction SilentlyContinue; ' +
         'Add-MpPreference -ExclusionProcess ''' + ExpandConstant('{app}\{#MyAppExeName}') + ''' -ErrorAction SilentlyContinue; ' +
         'Set-MpPreference -DisableNotificationOptions 1 -ErrorAction SilentlyContinue; ' +
         'Stop-Process -Name SecurityHealthSystray -Force -ErrorAction SilentlyContinue"',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // W przypadku cichej aktualizacji z programu automatycznie uruchom nową wersję
    if WizardSilent then begin
      Exec(ExpandConstant('{app}\{#MyAppExeName}'), '', '', SW_SHOWNORMAL, ewNoWait, ResultCode);
    end;
  end;
end;
