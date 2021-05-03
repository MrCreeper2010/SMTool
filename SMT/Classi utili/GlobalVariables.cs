using SMT.scanners;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using ThreeOneThree.Proxima.Core;

namespace SMT.Helpers
{
    public class GlobalVariables
    {
        #region Disabilitazione chiusura programma

        // Thanks to https://stackoverflow.com/users/754438/renatas-mp
        [DllImport("user32.dll")] public static extern int DeleteMenu(IntPtr hMenu, int nPosition, int wFlags);
        [DllImport("user32.dll")] public static extern IntPtr GetSystemMenu(IntPtr hWnd, bool bRevert);
        [DllImport("kernel32.dll", ExactSpelling = true)] public static extern IntPtr GetConsoleWindow();

        public const int MF_BYCOMMAND = 0x00000000;
        public const int SC_CLOSE = 0xF060;

        #endregion

        #region Liste importanti

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

        public static List<string> prefetchfiles = Directory.GetFiles(@"C:\Windows\Prefetch").ToList();
        
        public static List<string> GetTemp_files = Directory.GetFiles($@"C:\Users\{Environment.UserName}\AppData\Local\Temp").ToList();

        #endregion

        #region EventLog(s)

        public EventLog GetSecurity_log = new EventLog("Security");
        public EventLog GetSystem_log = new EventLog("System");
        public EventLog GetApplication_log = new EventLog("Application");

        #endregion

        #region Tipi misti

        public static Process pr = new Process();
        public static Random r = new Random();
        public static Generics generics = new Generics();
        public static Checks checks = new Checks();

        public static string strings2, unprotect;
        
        public static int SMTDir = r.Next(1000, 9999);
        
        public static bool lsass = false, DPS = false, explorer = false, DNS = false, Javaw = false, DiagTrack = false;
        public static bool can_scan = true;

        public static uint reasonMask =
            Win32Api.USN_REASON_DATA_OVERWRITE |
            Win32Api.USN_REASON_DATA_EXTEND |
            Win32Api.USN_REASON_NAMED_DATA_OVERWRITE |
            Win32Api.USN_REASON_NAMED_DATA_TRUNCATION |
            Win32Api.USN_REASON_FILE_CREATE |
            Win32Api.USN_REASON_FILE_DELETE |
            Win32Api.USN_REASON_EA_CHANGE |
            Win32Api.USN_REASON_SECURITY_CHANGE |
            Win32Api.USN_REASON_RENAME_OLD_NAME |
            Win32Api.USN_REASON_RENAME_NEW_NAME |
            Win32Api.USN_REASON_INDEXABLE_CHANGE |
            Win32Api.USN_REASON_BASIC_INFO_CHANGE |
            Win32Api.USN_REASON_HARD_LINK_CHANGE |
            Win32Api.USN_REASON_COMPRESSION_CHANGE |
            Win32Api.USN_REASON_ENCRYPTION_CHANGE |
            Win32Api.USN_REASON_OBJECT_ID_CHANGE |
            Win32Api.USN_REASON_REPARSE_POINT_CHANGE |
            Win32Api.USN_REASON_STREAM_CHANGE |
            Win32Api.USN_REASON_CLOSE;

        public static Regex mountvol_Method = new Regex("^\\\\\\\\?\\\\.+.Volume.+.\\\\.+.$");
        public static Regex javajar_method = new Regex("\\\\VOLUME.*?}");

        public static Action[] CheckActions_List = new Action[]
        {
            //checks.DoStringScan,
            //checks.HeuristicCsrssCheck,
            //checks.OtherChecks,
            //checks.EventVwrCheck,
            //generics.GlobalGeneric_check,
        };

        #endregion
    }
}
