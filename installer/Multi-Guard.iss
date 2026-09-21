; Inno Setup Script for Multi-Guard Antivirus & Endpoint Security
; Developed by Multi-Servis (https://multi-servis.pl)

#define MyAppName "Multi-Guard"
#define MyAppVersion "1.1.4.0"
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
Name: "startupicon"; Description: "Uruchamiaj Multi-Guard przy starcie systemu Windows"; GroupDescription: "Opcje systemowe:"

[Files]
; Główny plik wykonywalny oraz wszystkie biblioteki zebrane przez windeployqt
Source: "..\RELEASED\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Odinstaluj {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{commonstartup}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: startupicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Wyrejestrowanie z Windows Security Center przed deinstalacją
Filename: "{app}\{#MyAppExeName}"; Parameters: "--uninstall"; Flags: runhidden

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

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Key: String;
begin
  Result := True;
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
  end;
end;
