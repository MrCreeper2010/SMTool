using AuthenticodeExaminer;
using Pastel;
using SMT.Helpers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using ThreeOneThree.Proxima.Core;

namespace SMT.helpers
{
    public class SMTHelper
    {
        #region Variabili varie

        // Thanks to https://stackoverflow.com/users/754438/renatas-mp
        [DllImport("user32.dll")] public static extern int DeleteMenu(IntPtr hMenu, int nPosition, int wFlags);
        [DllImport("user32.dll")] public static extern IntPtr GetSystemMenu(IntPtr hWnd, bool bRevert);
        [DllImport("kernel32.dll", ExactSpelling = true)] public static extern IntPtr GetConsoleWindow();

        public static List<string> Csrss_files = new List<string>();
        public const int MF_BYCOMMAND = 0x00000000;
        public const int SC_CLOSE = 0xF060;
        public static Process pr = new Process();
        public static Random r = new Random();
        public static List<string> prefetchfiles = Directory.GetFiles(@"C:\Windows\Prefetch").ToList();
        public static List<string> GetTemp_files = Directory.GetFiles($@"C:\Users\{Environment.UserName}\AppData\Local\Temp").ToList();
        public static string strings2, unprotect;
        public static int SMTDir = r.Next(1000, 9999);
        public static bool lsass = false, DPS = false, DNS = false, Javaw = false, DiagTrack = false;
        #endregion

        public static DateTime PC_StartTime()
        {
            return DateTime.Now.AddMilliseconds(-Environment.TickCount);
        }

        public static void Wait() => Thread.Sleep(5000);

        public static bool journal_returnconditions(Win32Api.UsnEntry d)
        {
            bool true_or_false = false;

            if (GlobalVariables.suspy_extension.Contains(Path.GetExtension(d.Name.ToUpper()))
                        && TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp) >=
                        Process.GetProcessesByName(MinecraftMainProcess)[0].StartTime)
            {
                if (d.Name.ToUpper().Contains("JNATIVEHOOK")
                    && Path.GetExtension(d.Name.ToUpper()) == ".DLL")
                {
                    true_or_false = true;
                }
                else if (Path.GetExtension(d.Name.ToUpper()) != ".DLL")
                {
                    true_or_false = true;
                }
            }

            return true_or_false;
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
            if (Directory.Exists(@"C:\ProgramData"))
            {
                Directory.CreateDirectory($@"C:\ProgramData\SMT-{SMTDir}");

                strings2 = Path.Combine(Path.GetFullPath($@"C:\ProgramData\SMT-{SMTDir}"), "strings2.exe");
                unprotect = Path.Combine(Path.GetFullPath($@"C:\ProgramData\SMT-{SMTDir}"), "unprotect.exe");

                File.WriteAllBytes(strings2, Properties.Resources.strings2);
                File.WriteAllBytes(unprotect, Properties.Resources.unprotect);
            }
            else
            {
                SMT.RESULTS.Errors.Add(@"C:\ProgramData directory doesn't exist, please create it and restart smt");
                ConsoleHelper.WriteLine(@"C:\ProgramData directory doesn't exist, please create it and restart smt", ConsoleColor.Yellow);
                Console.ReadLine();
            }
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
            check.PriorityClass = ProcessPriorityClass.RealTime;
            check.WaitForExit();

            if (check.ExitCode != 0)
            {
                SMT.RESULTS.Errors.Add("AntiSS Tool detected, please check programs in background, some checks will be skipped");
                Console.WriteLine("There is a problem with some checks, please disable antivirus and restart SMT");
                Console.ReadLine();
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
                            process += "javaw";
                        }
                        else
                        {
                            process += "java";
                        }
                    }
                }
            }
            else if (Process.GetProcessesByName("javaw").Length > 0 && Process.GetProcessesByName("java").Length == 0)
            {
                process += "javaw";
            }
            else if (Process.GetProcessesByName("java").Length > 0 && Process.GetProcessesByName("javaw").Length == 0)
            {
                process += "java";
            }
            else if (Process.GetProcessesByName("javaw").Length == 0
                && Process.GetProcessesByName("java").Length == 0
                && Process.GetProcessesByName("launcher").Length > 0)
            {
                process += "launcher";
            }
            else
            {
                process += "";
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

        public static string GetSign(string file)
        {
            string signature = "";
            if (File.Exists(file))
            {
                FileInspector extractor = new FileInspector(file);
                SignatureCheckResult validationResult = extractor.Validate();

                switch (validationResult)
                {
                    case SignatureCheckResult.Valid:
                        signature = "Signed";
                        break;
                    case SignatureCheckResult.NoSignature:
                        signature = "Unsigned";
                        break;
                    case SignatureCheckResult.BadDigest:
                        signature = "Fake";
                        break;
                    default:
                        signature = "Other type of signature";
                        break;
                }
            }

            return signature;
        }

        public static string formatToPastebin()
        {
            string value_to_return = "";

            Results RESULTS = new Results();

            #region Write Results (Check 1)

            value_to_return += "Generic Informations: \n";

            value_to_return +=  "Alts:\n"; //fatto
            RESULTS.alts.Distinct().ToList().ForEach(alt => value_to_return += alt + "\n");

            #endregion

            /*
            #region Write Results (Check 2)

            value_to_return += "\n Checks:";

            if (RESULTS.Errors.Count > 0) // done
            {
                RESULTS.Errors.Distinct().ToList().ForEach(jna => value_to_return += jna + "\n");
            }

            if (RESULTS.possible_replaces.Count > 0) // done
            {
                value_to_return += "File's actions file:\n";
                RESULTS.possible_replaces.Sort();
                RESULTS.possible_replaces.Distinct().ToList().ForEach(replace => value_to_return += replace + "\n");
            }

            if (RESULTS.event_viewer_entries.Count > 0) // done
            {
                value_to_return += "\nBad Eventvwr log(s):\n";
                RESULTS.event_viewer_entries.Distinct().ToList().ForEach(eventvwr => value_to_return += eventvwr + "\n");
            }

            if (RESULTS.suspy_files.Count > 0) // done
            {
                value_to_return += "\nSuspy files: \n";
                RESULTS.suspy_files.Sort();
                RESULTS.suspy_files.Distinct().ToList().ForEach(eventvwr => value_to_return += eventvwr + "\n");
            }
            else
            {
                value_to_return += "\nWarning:\n";
                value_to_return += "- No suspicious file found, if user uses \"Kaspersky\" please disable it and rescan";
            }

            if (RESULTS.bypass_methods.Count > 0) // done
            {
                value_to_return += "\nBypass methods:\n";
                RESULTS.bypass_methods.Distinct().ToList().ForEach(eventvwr => value_to_return += eventvwr + "\n");
            }

            if (RESULTS.string_scan.Count > 0) // done
            {
                value_to_return += "\nString Scan:\n";
                RESULTS.string_scan.Distinct().ToList().ForEach(eventvwr => value_to_return += eventvwr + "\n");
            }

            #endregion
            */

            return value_to_return;
        }

        public static string HardwareID()
        {
            string return_value = "";

            var mbs = new ManagementObjectSearcher("Select ProcessorId From Win32_processor");
            ManagementObjectCollection mbsList = mbs.Get();
            foreach (ManagementObject mo in mbsList)
            {
                return_value = mo["ProcessorId"].ToString();
                break;
            }

            return return_value;
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

        public static string Detection(string detection_type, string detection, string time)
        {
            string detection_return = "";

            switch (detection_type)
            {
                case "Deleted":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(240, 52, 52))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case "Bypass method":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(240, 52, 52))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case "Moved/Renamed":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(235, 149, 50))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case "Suspicious File (Digital signature check)":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(240, 255, 0))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case "Suspicious File (Suspicious behavior)":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(240, 255, 0))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case "Suspicious signature":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(240, 255, 0))} {"]".Pastel(Color.White)} {detection}";
                    break;
                case "Fake digital signature":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(254, 250, 212))} {"]".Pastel(Color.White)} {detection}";
                    break;
                case "Out of Instance":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(240, 255, 0))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case "Unknow type of signature":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(240, 255, 0))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case "In Instance":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(0, 230, 64))} {"]".Pastel(Color.White)} {detection}";
                    break;
                case "Wmic Method":
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(140, 20, 252))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case "Stage Progress":
                    detection_return = $@"{"[".Pastel(Color.White)}{$"+".Pastel(Color.FromArgb(0, 230, 64))}{"]".Pastel(Color.White)} -> { $"{time}".Pastel(Color.FromArgb(165, 229, 250))}";
                    break;
            }

            return detection_return;
        }

        public static string DownloadString(string url)
        {
            using (WebClient wc = new WebClient())
            {
                try
                {
                    return wc.DownloadString(url);
                }
                catch
                {
                    ConsoleHelper.WriteLine("Please check your connection!", ConsoleColor.Yellow);
                    Thread.Sleep(5000);
                    Environment.Exit(1);
                    return string.Empty;
                }
            }
        }

        public static void SaveAllFiles()
        {
            //csrss
            try
            {
                if (Process.GetProcessesByName("csrss")[0].PagedMemorySize64 > Process.GetProcessesByName("csrss")[1].PagedMemorySize64)
                {
                    UnProtectProcess(Process.GetProcessesByName("csrss")[0].Id);
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -pid {Process.GetProcessesByName("csrss")[0].Id} > C:\ProgramData\SMT-{SMTDir}\csrss.txt");
                }
                else
                {
                    UnProtectProcess(Process.GetProcessesByName("csrss")[1].Id);
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -pid {Process.GetProcessesByName("csrss")[1].Id} > C:\ProgramData\SMT-{SMTDir}\csrss.txt");
                }
            }
            catch
            {

            }

            //pcasvc (non scanna più)
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

            //DPS
            try
            {
                if (GetPID("DPS") != " 0 ")
                {
                    UnProtectProcess(Convert.ToInt32(GetPID("DPS")));
                    SaveFile($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\strings2.exe -l 19 -pid {GetPID("DPS")} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\Specific.txt");
                    DPS = true;
                }
                else
                {
                    SMT.RESULTS.bypass_methods.Add("Generic Bypass method (DPS process missed)");
                }
            }
            catch { }

            //lsass
            try
            {
                if (Process.GetProcessesByName("lsass")[0].Id > 0)
                {
                    UnProtectProcess(Convert.ToInt32(Process.GetProcessesByName("lsass")[0].Id));
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -l 6 -pid {Process.GetProcessesByName("lsass")[0].Id} > C:\ProgramData\SMT-{SMTDir}\Browser.txt");
                    lsass = true;
                }
            }
            catch { }

            //DNS
            try
            {
                if (GetPID("dnscache") != " 0 ")
                {
                    UnProtectProcess(Convert.ToInt32(GetPID("dnscache")));
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -l 6 -pid {GetPID("dnscache")} > C:\ProgramData\SMT-{SMTDir}\dns.txt");
                    DNS = true;
                }
                else
                {
                    SMT.RESULTS.bypass_methods.Add("Generic Bypass method (DNScache process missed)");
                }
            }
            catch { }

            //DiagTrack
            try
            {
                if (GetPID("DiagTrack") != " 0 ")
                {
                    UnProtectProcess(Convert.ToInt32(GetPID("DiagTrack")));
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -pid {GetPID("DiagTrack")} > C:\ProgramData\SMT-{SMTHelper.SMTDir}\utcsvc.txt");

                    string[] DiagTrack_lines = File.ReadAllLines($@"C:\ProgramData\SMT-{SMTDir}\utcsvc.txt");
                    if (DiagTrack_lines.ToList().Contains("cmd.exe")
                        && DiagTrack_lines.ToList().Contains("del")
                        && DiagTrack_lines.ToList().Contains(".pf"))
                    {
                        SMT.RESULTS.string_scan.Add("Found generic prefetch's file(s) Self-destruct");
                    }
                }
                else
                {
                    SMT.RESULTS.bypass_methods.Add("Generic Bypass method (DiagTrack process missed)");
                }
            }
            catch { }
        }
    }
}