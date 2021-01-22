﻿using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace SMT.helpers
{

    //[StructLayout(LayoutKind.Sequential)]
    //public struct FileReparseTagInformation
    //{
    //    public long FileReferenceNumber;
    //    public ReparseTag Tag;
    //}

    //public struct FileData
    //{
    //    public string FileName;
    //    public ReparseBuffer Reparse;
    //}
    public class SMTHelper
    {
        #region Variables

        // Thanks to https://stackoverflow.com/users/754438/renatas-mp
        [DllImport("user32.dll")] public static extern int DeleteMenu(IntPtr hMenu, int nPosition, int wFlags);
        [DllImport("user32.dll")] public static extern IntPtr GetSystemMenu(IntPtr hWnd, bool bRevert);
        [DllImport("kernel32.dll", ExactSpelling = true)] public static extern IntPtr GetConsoleWindow();

        public const int MF_BYCOMMAND = 0x00000000;
        public const int SC_CLOSE = 0xF060;
        public static Process pr = new Process();
        public static Process[] prlist = Process.GetProcesses();
        public static ProcessStartInfo startInfo = new ProcessStartInfo();
        public static Random r = new Random();
        public static string[] prefetchfiles = Directory.GetFiles(@"C:\Windows\Prefetch");
        public static string[] MinecraftProcesses = new string[] { "javaw", "launcher", "Lunar Client" };
        public static string str, result, result2, sigcheck, strings2, unprotect;
        public static int SMTDir = r.Next(1000, 9999);
        public static bool DPS = false, DNS = false, Javaw = false, DiagTrack = false;
        public static string Csrss_Dir = "";

        public static Regex virgole = new Regex(",");
        public static Regex apostrofo = new Regex("\"");
        public static Regex GetID = new Regex("\",0.*?,0x");
        public static Regex leva_primevirgole = new Regex("\",.*?,");
        public static Regex replace0x = new Regex(",0x");
        public static Regex getaddress = new Regex("0.*?$");
        public static Regex CinuqueVirgole = new Regex(@",.*?\|.*?,");
        public static Regex TraApostrofo = new Regex("\".*?\"");
        #endregion

        public static DateTime PC_StartTime()
        {
            return DateTime.Now.AddMilliseconds(-Environment.TickCount);
        }

        public static void Exit()
        {
            Thread.Sleep(5000);
        }

        public static DateTime GetFileDateTime(string line)
        {
            string data_fiunzoa;

            data_fiunzoa = CinuqueVirgole.Replace(line, "");
            Match GetData = TraApostrofo.Match(data_fiunzoa);
            data_fiunzoa = virgole.Replace(GetData.Value, "");
            data_fiunzoa = apostrofo.Replace(data_fiunzoa, "");

            return DateTime.Parse(data_fiunzoa);
        }

        public static Match GetFirstID(string line)
        {
            string directory;

            Match GetDirectory = GetID.Match(line);
            directory = leva_primevirgole.Replace(GetDirectory.Value, "");
            directory = replace0x.Replace(directory, "");
            directory = virgole.Replace(directory, "");
            directory = apostrofo.Replace(directory, "");
            return getaddress.Match(directory);
        }

        public static string GetSecondID(string line)
        {
            string directory2 = "";
            Regex GetSecondID = new Regex("\",00.*?,");

            Match GetDirectory2 = GetSecondID.Match(line);
            directory2 = virgole.Replace(GetDirectory2.Value, "");
            return apostrofo.Replace(directory2, "");
        }

        public static string GetPID(string process)
        {
            string finalpid = "";

            pr.StartInfo.FileName = "sc.exe";
            pr.StartInfo.Arguments = "queryex \"" + process + "\"";
            pr.StartInfo.UseShellExecute = false;
            pr.StartInfo.RedirectStandardOutput = true;
            pr.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            pr.Start();
            pr.WaitForExit();
            string output = pr.StandardOutput.ReadToEnd();
            pr.Close();

            if (output.IndexOf(process) != -1)
            {
                bool getPid = false;
                string[] words = output.Split(':');
                foreach (string word in words)
                {
                    if (word.IndexOf("PID") != -1 && getPid == false)
                    {
                        getPid = true;
                    }
                    else if (getPid)
                    {
                        string[] pid = word.Split('\r');
                        finalpid += pid[0];
                    }
                }
            }
            else
            {
                finalpid = "Unexpected error";
            }

            return finalpid;
        }

        public static void ExtractFile()
        {
            Directory.CreateDirectory($@"C:\ProgramData\SMT-{SMTDir}");

            sigcheck = Path.Combine(Path.GetFullPath($@"C:\ProgramData\SMT-{SMTDir}"), "sigcheck.exe");
            strings2 = Path.Combine(Path.GetFullPath($@"C:\ProgramData\SMT-{SMTDir}"), "strings2.exe");
            unprotect = Path.Combine(Path.GetFullPath($@"C:\ProgramData\SMT-{SMTDir}"), "unprotect.exe");

            File.WriteAllBytes(sigcheck, Properties.Resources.sigcheck64);
            File.WriteAllBytes(strings2, Properties.Resources.strings2);
            File.WriteAllBytes(unprotect, Properties.Resources.unprotecting_process);
        }

        public static bool ContainsUnicodeCharacter(string input)
        {
            ///Original post: https://stackoverflow.com/questions/4459571/how-to-recognize-if-a-string-contains-unicode-chars

            const int MaxAnsiCode = 255;

            return input.Any(c => c > MaxAnsiCode);
        }

        public static void SaveFile(string arg)
        {
            ProcessStartInfo scan = new ProcessStartInfo()
            {
                FileName = @"CMD.exe",
                Arguments = $@"/C {arg}",
                UseShellExecute = false,
                RedirectStandardOutput = true,

            };

            Process check = Process.Start(scan);
            check.WaitForExit();

            if (check.ExitCode != 0)
            {
                ConsoleHelper.WriteLine("AntiSS Tool detected, please check programs in background, some checks will be skipped", ConsoleColor.Red);
            }

            check.Close();
        }

        public static string GetCorrectMCProcess()
        {
            string process = "";

            if (Process.GetProcessesByName("javaw").Length > 0 && Process.GetProcessesByName("java").Length > 0)
            {
                using (Process Javaw = Process.GetProcessesByName("javaw")[0])
                {
                    using (Process Java = Process.GetProcessesByName("java")[0])
                    {
                        if (Javaw.WorkingSet64 > Java.WorkingSet64)
                        {
                            for (int i = 0; i < Process.GetProcessesByName("javaw").Length; i++)
                            {
                                for (int j = 0; j < Process.GetProcessesByName("javaw")[i].Modules.Count; j++)
                                {
                                    if (Process.GetProcessesByName("javaw")[i].Modules[j].ModuleName.Contains("OpenAL"))
                                    {
                                        process += "javaw";
                                        break;
                                    }
                                }
                            }
                        }
                        else
                        {
                            for (int i = 0; i < Process.GetProcessesByName("java").Length; i++)
                            {
                                for (int j = 0; j < Process.GetProcessesByName("java")[i].Modules.Count; j++)
                                {
                                    if (Process.GetProcessesByName("java")[i].Modules[j].ModuleName.Contains("OpenAL"))
                                    {
                                        process += "java";
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else if (Process.GetProcessesByName("javaw").Length > 0 && Process.GetProcessesByName("java").Length == 0)
            {
                for (int i = 0; i < Process.GetProcessesByName("javaw").Length; i++)
                {
                    for (int j = 0; j < Process.GetProcessesByName("javaw")[i].Modules.Count; j++)
                    {
                        if (Process.GetProcessesByName("javaw")[i].Modules[j].ModuleName.Contains("OpenAL")
                            && Process.GetProcessesByName("javaw")[i].PagedMemorySize64 > 0)
                        {
                            process += "javaw";
                            break;
                        }
                    }
                }
            }
            else if (Process.GetProcessesByName("java").Length > 0 && Process.GetProcessesByName("javaw").Length == 0)
            {
                for (int i = 0; i < Process.GetProcessesByName("java").Length; i++)
                {
                    for (int j = 0; j < Process.GetProcessesByName("java")[i].Modules.Count; j++)
                    {
                        if (Process.GetProcessesByName("java")[i].Modules[j].ModuleName.Contains("OpenAL"))
                        {
                            process += "java";
                            break;
                        }
                    }
                }
            }

            return process;
        }

        public static string MinecraftMainProcess = GetCorrectMCProcess();

        public static bool isCorrectMC()
        {
            bool isMc = false;

            if (Process.GetProcessesByName(GetCorrectMCProcess()).Length > 0)
            {
                isMc = true;
            }

            return isMc;
        }

        public static string CheaterJoke()
        {
            string Joke = "";
            int counter = 0;
            Random random = new Random();
            int FraseRandom = random.Next(1, 22);

            WebClient client = new WebClient();
            using (Stream stream = client.OpenRead("https://pastebin.com/raw/FP7qvFYL"))
            {
                using (StreamReader reader = new StreamReader(stream))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        counter++;
                        if (FraseRandom == counter)
                        {
                            Joke += line;
                        }
                    }
                }
            }

            return Joke;
        }

        //public static NtFile OpenReparseDirectory(string volume)
        //{
        //    return NtFile.Open($@"\??\{volume}\$Extend\$Reparse:$R:$INDEX_ALLOCATION", null, FileAccessRights.GenericRead | FileAccessRights.Synchronize,
        //        FileShareMode.Read, FileOpenOptions.OpenForBackupIntent | FileOpenOptions.SynchronousIoNonAlert);
        //}

        //public static void EnablePrivileges()
        //{
        //    using (NtToken token = NtToken.OpenProcessToken())
        //    {
        //        token.SetPrivilege(TokenPrivilegeValue.SeBackupPrivilege, PrivilegeAttributes.Enabled);
        //        token.SetPrivilege(TokenPrivilegeValue.SeRestorePrivilege, PrivilegeAttributes.Enabled);
        //    }
        //}

        //public static void GetFileData(NtFile volume, ReparseTag tag, long fileid)
        //{
        //    using (NtFile file = NtFile.OpenFileById(volume, fileid, FileAccessRights.ReadAttributes | FileAccessRights.Synchronize,
        //        FileShareMode.None, FileOpenOptions.DirectoryFile | FileOpenOptions.SynchronousIoNonAlert | FileOpenOptions.OpenForBackupIntent))
        //    {
        //        //string filename = file.GetWin32PathName(NtApiDotNet.Win32.Win32PathNameFlags.None, false).GetResultOrDefault(fileid.ToString());

        //        try
        //        {
        //            SMT.RESULTS.suspy_files.Add(file.GetFileName(true).ToString());
        //        }
        //        catch (NtException)
        //        {

        //        }
        //    }
        //}

        public static string GetSign(string file)
        {
            string signature = "";

            Console.OutputEncoding = Encoding.UTF8;

            pr.StartInfo.FileName = $@"C:\ProgramData\SMT-{SMTDir}\sigcheck.exe";
            pr.StartInfo.Arguments = "/C -a -accepteula \"" + file + "\"";
            pr.StartInfo.UseShellExecute = false;
            pr.StartInfo.RedirectStandardOutput = true;
            pr.Start();
            pr.WaitForExit();
            signature += pr.StandardOutput.ReadToEnd();
            pr.Close();

            return signature;
        }

        public static void UnProtectProcess(int PID)
        {
            Console.OutputEncoding = Encoding.UTF8;

            pr.StartInfo.FileName = $@"C:\ProgramData\SMT-{SMTDir}\unprotect.exe";
            pr.StartInfo.Arguments = $"/d {PID}";
            pr.StartInfo.UseShellExecute = false;
            pr.StartInfo.RedirectStandardOutput = true;
            pr.Start();
            pr.WaitForExit();
        }

        public static bool IsExternalClient(string SuspyFile)
        {
            bool isClient = false;

            if (File.ReadLines(SuspyFile).First()[0] == 'M'
                            && File.ReadLines(SuspyFile).First()[1] == 'Z'
                            && File.ReadLines(SuspyFile).First() == "This program cannot be run in DOS mode"
                            && File.ReadAllText(SuspyFile).Contains("__std_type_info_destroy_list")
                            && File.ReadAllText(SuspyFile).Contains("__C_specific_handler")
                            && File.ReadAllText(SuspyFile).Contains("memset")
                            && (File.ReadAllText(SuspyFile).Contains("ReadProcessMemory")
                            || File.ReadAllText(SuspyFile).Contains("WriteProcessMemory")
                            || File.ReadAllText(SuspyFile).Contains("AllocConsole")
                            || File.ReadAllText(SuspyFile).Contains("GetKeyState")
                            || File.ReadAllText(SuspyFile).Contains("GetAsyncKeyState")))
            {
                isClient = true;
            }

            return isClient;
        }

        public static void SaveAllFiles()
        {
            Header header = new Header();
            header.Stages(0, "SMT is loading some informations");

            //csrss
            try
            {
                UnProtectProcess(Process.GetProcessesByName("csrss")[0].Id);
                SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 4 -pid {Process.GetProcessesByName("csrss")[0].Id} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\csrss.txt");
            }
            catch
            {

            }

            //pcasvc
            try
            {
                if (GetPID("pcasvc") != " 0 ")
                {

                }
                else
                {
                    SMT.RESULTS.bypass_methods.Add("Generic Bypass method (PcaSvc process missed)");
                }
            }
            catch { }

            //DPS (Specific)
            try
            {
                if (GetPID("DPS") != " 0 ")
                {
                    UnProtectProcess(Convert.ToInt32(GetPID("DPS")));
                    SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 19 -pid {SMTHelper.GetPID("DPS")} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\Specific.txt");
                    DPS = true;
                }
                else
                {
                    SMT.RESULTS.bypass_methods.Add("Generic Bypass method (DPS process missed)");
                }
            }
            catch { }

            //DNS
            try
            {
                if (GetPID("Dnscache") != " 0 ")
                {
                    UnProtectProcess(Convert.ToInt32(GetPID("Dnscache")));
                    SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 6 -pid {SMTHelper.GetPID("Dnscache")} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\Browser.txt");
                    DNS = true;
                }
                else
                {
                    SMT.RESULTS.bypass_methods.Add("Generic Bypass method (DNS process missed)");
                }
            }
            catch { }

            //DiagTrack
            try
            {
                if (GetPID("DiagTrack") != " 0 ")
                {
                    UnProtectProcess(Convert.ToInt32(GetPID("DiagTrack")));
                    SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 4 -pid {SMTHelper.GetPID("DiagTrack")} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\utcsvc.txt");
                    DiagTrack = true;
                }
                else
                {
                    SMT.RESULTS.bypass_methods.Add("Generic Bypass method (DiagTrack process missed)");
                }
            }
            catch { }

            header.Stages(0, "SMT is loading some informations");
        }
    }
}
