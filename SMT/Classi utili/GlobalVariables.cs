using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace SMT.Helpers
{
    public class GlobalVariables
    {
        // Thanks to https://stackoverflow.com/users/754438/renatas-mp
        [DllImport("user32.dll")] public static extern int DeleteMenu(IntPtr hMenu, int nPosition, int wFlags);
        [DllImport("user32.dll")] public static extern IntPtr GetSystemMenu(IntPtr hWnd, bool bRevert);
        [DllImport("kernel32.dll", ExactSpelling = true)] public static extern IntPtr GetConsoleWindow();

        public const int MF_BYCOMMAND = 0x00000000;
        public const int SC_CLOSE = 0xF060;

        public static readonly List<string> suspy_extension = new List<string>()
        {
            ".EXE",
            ".BAT",
            ".CMD",
            ".COM",
            ".PIF",
            ".PF",
            ".DLL",
        };

        public static readonly List<string> suspy_imports = new List<string>()
        {
            "ReadProcessMemory",
            "WriteProcessMemory",
            "GetKeyState",
            "GetAsyncKeyState",
            "mouse_event",
            "VirtualQueryEx",
            "SendMessage",
        };

        public static Process pr = new Process();
        public static Random r = new Random();
        public static List<string> prefetchfiles = Directory.GetFiles(@"C:\Windows\Prefetch").ToList();
        public static List<string> GetTemp_files = Directory.GetFiles($@"C:\Users\{Environment.UserName}\AppData\Local\Temp").ToList();
        public static string strings2, unprotect;
        public static int SMTDir = r.Next(1000, 9999);
        public static bool lsass = false, DPS = false, explorer = false, DNS = false, Javaw = false, DiagTrack = false;

    }
}
