using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class SignEX
{
    IntPtr handle;
    public SignEX(string ProcessName) { handle = OpenProcess(2035711, false, GetProcessID(ProcessName)); }
    public SignEX(int pID) { handle = OpenProcess(2035711, false, pID); }
    public SignEX(IntPtr pHandle) { handle = pHandle; }
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
    private int GetProcessID(string name) //gets process id by process name
    {
        Process[] p = Process.GetProcessesByName(name);
        return p.Length > 0 ? p[0].Id : -1;
    }
    private int SignScan(byte[] bytes_scan) //searching for bytes
    {
        MEMORY_BASIC_INFORMATION zero = new MEMORY_BASIC_INFORMATION();
        int baseAddress = 0, num = 0;
        byte[] numArray;
        while (baseAddress <= Int32.MaxValue)
        {
            VirtualQueryEx(handle, (IntPtr)baseAddress, out zero, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
            int firstpart_regionsize = (int)zero.RegionSize / 2;
            int secondpart_regionsize = (int)zero.RegionSize - firstpart_regionsize;

            #region 1° parte

            if (baseAddress != (int)zero.BaseAddress + firstpart_regionsize)
            {
                baseAddress = (int)zero.BaseAddress + firstpart_regionsize;
                try
                {
                    numArray = new byte[firstpart_regionsize];
                }
                catch 
                { 
                    return -1; 
                }
                ReadProcessMemory(handle, zero.BaseAddress, numArray, firstpart_regionsize, out _);
                int x = -1;
                while (++x < firstpart_regionsize)
                    if (numArray[x] == bytes_scan[0])
                        for (int i = 0; i < (int)bytes_scan.Length; i++)
                            if (numArray[i + x] != bytes_scan[i])
                            {
                                num = 0;
                                break;
                            }
                            else
                            {
                                num++;
                                if (num == (int)bytes_scan.Length)
                                    return (int)zero.BaseAddress + x;
                            }
            }
            else break;

            #endregion

            #region 2° parte

            if (baseAddress != (int)zero.BaseAddress + secondpart_regionsize)
            {
                baseAddress = (int)zero.BaseAddress + secondpart_regionsize;
                try
                {
                    numArray = new byte[secondpart_regionsize];
                }
                catch
                {
                    return -1;
                }
                ReadProcessMemory(handle, zero.BaseAddress, numArray, secondpart_regionsize, out _);
                int x = -1;
                while (++x < secondpart_regionsize)
                    if (numArray[x] == bytes_scan[0])
                        for (int i = 0; i < (int)bytes_scan.Length; i++)
                            if (numArray[i + x] != bytes_scan[i])
                            {
                                num = 0;
                                break;
                            }
                            else
                            {
                                num++;
                                if (num == (int)bytes_scan.Length)
                                    return (int)zero.BaseAddress + x;
                            }
            }
            else break;

            #endregion

        }
        return -1;
    }

    /// <summary>
    /// Returns True or False whether code was injected or not
    /// </summary>
    /// <param name="bytes_scan"></param>
    /// <param name="bytes_write"></param>
    /// <returns></returns>
    public bool WriteBytes(byte[] bytes_scan, byte[] bytes_write)
    {
        int num = SignScan(bytes_scan);
        if (num != -1)
            return WriteProcessMemory(handle, (IntPtr)num, bytes_write, (uint)bytes_write.Length, out _);
        return false;
    }

    #region kernel32
    [DllImport("kernel32.dll", CharSet = CharSet.None, ExactSpelling = false, SetLastError = true)]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
    [DllImport("kernel32.dll", CharSet = CharSet.None, ExactSpelling = false)]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll", CharSet = CharSet.None, ExactSpelling = false, SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);
    [DllImport("kernel32.dll", CharSet = CharSet.None, ExactSpelling = false, SetLastError = true)]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, UIntPtr lpNumberOfBytesWritten);
    private void WriteProcessMemory(IntPtr handle, IntPtr addr, object bytes_write, uint length, out UIntPtr dammy)
    {
        throw new NotImplementedException();
    }
    [DllImport("kernel32.dll", CharSet = CharSet.None, ExactSpelling = false)]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
    #endregion
}
