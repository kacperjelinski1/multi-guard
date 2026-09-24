#define MyAppName "Multi-Guard"
#define MyAppVersion "2.0.4.0"
#define MyAppPublisher "Multi-Servis"
#define MyAppURL "https://multi-servis.pl/"
#define MyAppExeName "Multi-Guard.exe"

[Setup]
AppId={{FC9A1A31-4F2E-4D5F-A364-7D68826F8B2C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
OutputBaseFilename=Multi-Guard-Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\resources\app.ico

[Languages]
Name: "polish"; MessagesFile: "compiler:Languages\Polish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\RELEASED\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
; We can keep the dummy folders for logs/quarantine just in case
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
// No custom code needed for the pure UI version