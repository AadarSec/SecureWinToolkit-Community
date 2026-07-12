#define MyAppName "SecureWin Toolkit"
#define MyAppVersion "1.0 RC1"
#define MyAppPublisher "AadarSec"
#define MyAppExeName "SecureWinToolkit.exe"

[Setup]
AppId={{9F4B2E9D-4E64-4C6E-9D85-123456789ABC}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\SecureWin Toolkit
DefaultGroupName=SecureWin Toolkit
OutputDir=Output
OutputBaseFilename=SecureWinToolkitSetup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
Source: "..\dist\SecureWinToolkit\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\SecureWin Toolkit"; Filename: "{app}\SecureWinToolkit.exe"
Name: "{autodesktop}\SecureWin Toolkit"; Filename: "{app}\SecureWinToolkit.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\SecureWinToolkit.exe"; Description: "Launch SecureWin Toolkit"; Flags: nowait postinstall skipifsilent