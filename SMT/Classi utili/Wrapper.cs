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
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using ThreeOneThree.Proxima.Core;

namespace SMT.helpers
{
    public class Wrapper : GlobalVariables
    {
        public static Results RESULTS = new Results();

        public enum DETECTION_VALUES
        {
            FILE_DELETED = 0,
            FILE_MOVED_RENAMED = 1,
            BYPASS_METHOD = 2,
            SUSP_BEHAVIOR = 3, //Suspicious File (Suspicious behavior)
            UNSIGNED = 4, //Suspicious File (Digital signature check)
            SUSP_SIGN = 5,
            FAKE_SIGN = 6,
            UNKN_SIGN = 7,
            OUT_INSTANCE = 8,
            IN_INSTANCE = 9,
            WMIC = 10, //DA ELIMINARE
            STAGE_PRC = 11,
        };

        #region Console Utilities

        public static void WriteLine(string text, ConsoleColor consoleColor = ConsoleColor.White)
        {
            ConsoleColor backupColor = Console.ForegroundColor;
            Console.ForegroundColor = consoleColor;
            Console.WriteLine(text);
            Console.ForegroundColor = backupColor;
        }

        public static void Write(string text, ConsoleColor consoleColor = ConsoleColor.White)
        {
            ConsoleColor backupColor = Console.ForegroundColor;
            Console.ForegroundColor = consoleColor;
            Console.Write(text);
            Console.ForegroundColor = backupColor;
        }

        private static void ThrowException()
        {
            RESULTS.Errors.Add("An error occured meanwhile SMT was scanning, please restart SMT");
        }

        public static void runCheckAsync(Action check)
        {
            try
            {
#pragma warning disable CS1998 // Il metodo asincrono non contiene operatori 'await', pertanto verrà eseguito in modo sincrono
                SMT_Main.tasks.Add(Task.Factory.StartNew(async () => check()));
#pragma warning restore CS1998 // Il metodo asincrono non contiene operatori 'await', pertanto verrà eseguito in modo sincrono
            }
            catch { ThrowException(); }
        }


        public static bool GL_Contains(string source, string toCheck)
        {
            return source.IndexOf(toCheck, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static void GoodBye()
        {
            Generics generics = new Generics();

            WriteLine("\nHave a nice day! developed by MrCreeper2010", ConsoleColor.Yellow);
            Console.Write("\nPress ENTER to exit");
            Console.ReadLine();
            Console.Write("\nConfirm exit -> press ENTER");
            Console.ReadLine();
            generics.Clean();
        }

        #endregion

        #region File/Comandi/Cartelle Utilities

        public static DateTime PC_StartTime()
        {
            return DateTime.Now.AddMilliseconds(-Environment.TickCount);
        }

        public static bool IsFileLocked(FileInfo file)
        {
            try
            {
                using (FileStream stream = file.Open(FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    stream.Close();
                }
            }
            catch (IOException)
            {
                return true;
            }

            return false;
        }

        public static void Wait() => Thread.Sleep(5000);

        public static bool journal_returnconditions(Win32Api.UsnEntry UsnEntry)
        {
            bool true_or_false = false;

            if (suspy_extension.Contains(Path.GetExtension(UsnEntry.Name.ToUpper())))
            {
                if (TimeZone.CurrentTimeZone.ToLocalTime(UsnEntry.TimeStamp)
                    >= Process.GetProcessesByName(MinecraftMainProcess)[0].StartTime)
                {
                    if (GL_Contains(UsnEntry.Name, "Jnativehook") && GL_Contains(UsnEntry.Name, ".dll"))
                    {
                        true_or_false = true;
                    }
                    else if (!GL_Contains(UsnEntry.Name, ".dll"))
                    {
                        true_or_false = true;
                    }
                }
            }

            return true_or_false;
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
                RESULTS.Errors.Add(@"C:\ProgramData directory doesn't exist, please create it and restart smt");
                WriteLine(@"C:\ProgramData directory doesn't exist, please create it and restart smt", ConsoleColor.Yellow);
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
                RESULTS.Errors.Add("AntiSS Tool detected, please check programs in background, some checks will be skipped");
                Console.WriteLine("There is a problem with some checks, please disable antivirus and restart SMT");
                Console.ReadLine();
            }

            check.Close();
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

        public static string HardwareID()
        {
            /*
             * Massì basterà per questi shitty bypasser
             */

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

        public static string Detection(DETECTION_VALUES detection_type, string detection, string time)
        {
            string detection_return = "";

            switch (detection_type)
            {
                #region File types

                case DETECTION_VALUES.FILE_DELETED:
                    detection_return = $@"{"[".Pastel(Color.White)} {$"DELETED".Pastel(Color.FromArgb(240, 52, 52))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case DETECTION_VALUES.BYPASS_METHOD:
                    detection_return = $@"{"[".Pastel(Color.White)} {$"BYPASS METHOD".Pastel(Color.FromArgb(240, 52, 52))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case DETECTION_VALUES.FILE_MOVED_RENAMED:
                    detection_return = $@"{"[".Pastel(Color.White)} {$"MOVED OR RENAMED".Pastel(Color.FromArgb(235, 149, 50))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;

                #endregion

                #region Signature type

                case DETECTION_VALUES.UNSIGNED:
                    detection_return = $@"{"[".Pastel(Color.White)} {$"UNSIGNED".Pastel(Color.FromArgb(240, 255, 0))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case DETECTION_VALUES.SUSP_BEHAVIOR:
                    detection_return = $@"{"[".Pastel(Color.White)} {$"SUSPY BEHAVIOR".Pastel(Color.FromArgb(240, 255, 0))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                //case DETECTION_VALUES.SUSP_SIGN: //TODO
                //    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(240, 255, 0))} {"]".Pastel(Color.White)} {detection}";
                //    break;
                case DETECTION_VALUES.FAKE_SIGN:
                    detection_return = $@"{"[".Pastel(Color.White)} {$"FAKE SIGNATURE".Pastel(Color.FromArgb(254, 250, 212))} {"]".Pastel(Color.White)} {detection}";
                    break;
                case DETECTION_VALUES.UNKN_SIGN:
                    detection_return = $@"{"[".Pastel(Color.White)} {$"UNKNOW SIGNATURE".Pastel(Color.FromArgb(240, 255, 0))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;

                #endregion

                #region Others

                case DETECTION_VALUES.OUT_INSTANCE:
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(240, 255, 0))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case DETECTION_VALUES.IN_INSTANCE:
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(0, 230, 64))} {"]".Pastel(Color.White)} {detection}";
                    break;

                case DETECTION_VALUES.WMIC:
                    detection_return = $@"{"[".Pastel(Color.White)} {$"{detection_type}".Pastel(Color.FromArgb(140, 20, 252))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;

                case DETECTION_VALUES.STAGE_PRC:
                    detection_return = $@"{"[".Pastel(Color.White)}{$"+".Pastel(Color.FromArgb(0, 230, 64))}{"]".Pastel(Color.White)} -> { $"{time}".Pastel(Color.FromArgb(165, 229, 250))}";
                    break;

                    #endregion
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
                    WriteLine("Please check your connection!", ConsoleColor.Yellow);
                    Thread.Sleep(5000);
                    Environment.Exit(1);
                    return string.Empty;
                }
            }
        }

        public static string calcoloSHA256(FileStream file)
        {
            var sha = new SHA256Managed();

            byte[] bytes = sha.ComputeHash(file);
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
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

            /*

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
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -l 19 -pid {GetPID("DPS")} > C:\ProgramData\SMT-{SMTDir}\Specific.txt");
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
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -pid {GetPID("DiagTrack")} > C:\ProgramData\SMT-{SMTDir}\utcsvc.txt");

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

            */

            //Explorer
            try
            {
                if (Process.GetProcessesByName("explorer")[0].Id.ToString().Length > 0)
                {
                    //UnProtectProcess(Convert.ToInt32(GetPID("explorer")));
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -l 6 -pid {Process.GetProcessesByName("explorer")[0].Id} > C:\ProgramData\SMT-{SMTDir}\explorer.txt");
                    explorer = true;
                }
                else
                {
                    RESULTS.bypass_methods.Add("Generic Bypass method (Explorer process missed)");
                }
            }
            catch
            {

            }
        }

        #endregion

        #region MC Utilities

        public static string MinecraftMainProcess = GetCorrectMCProcess();

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

        public static bool isCorrectMC()
        {
            bool isMc = false;

            if (Process.GetProcessesByName(GetCorrectMCProcess()).Length > 0)
            {
                isMc = true;
            }

            return isMc;
        }

        public static bool isMCRunning()
        {
            bool return_value = false;

            if (isCorrectMC())
            {
                return_value = true;
            }
            else
            {
                Wrapper.WriteLine("[!] Minecraft missed, press any key to exit", ConsoleColor.Yellow);
                Console.ReadLine();
                Environment.Exit(0);

                return_value = false;
            }

            return return_value;
        }

        #endregion

        #region Process Utilities

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

        public static string getCommand(string volume_name, string rfn)
        {
            string return_value = "";

            Process p = new Process();
            // Redirect the output stream of the child process.
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.Arguments = $"/C fsutil file queryfilenamebyid {volume_name} {rfn}";
            p.Start();

            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();

            if (!output.Contains(@"\\?\"))
                return_value = "";
            else
            {
                Regex rgx = new Regex("\\\\.*?$");
                var d = rgx.Match(output);
                return_value = d.Value;
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

        #endregion

        #region Write List's results

        public static void enumResults()
        {
            #region Write Results (Check 1)
            WriteLine("Generic Informations: \n", ConsoleColor.Green);

            WriteLine("Alts:\n", ConsoleColor.Yellow); //fatto
            RESULTS.alts.Distinct().ToList().ForEach(alt => WriteLine("- " + alt));

            WriteLine("\nRecycle.bin:\n", ConsoleColor.Yellow); //fatto
            foreach (KeyValuePair<string, string> recycleBin in RESULTS.recyble_bins)
            {
                WriteLine($"- {recycleBin.Key} ({recycleBin.Value})");
            }

            if (RESULTS.recording_softwares.Count > 0)
            {
                WriteLine("\nRecording Software(s):\n ", ConsoleColor.Yellow);

                RESULTS.recording_softwares.ForEach(recording => WriteLine("- " + recording));
            }
            else
            {
                WriteLine("\nRecording Software(s):\n ", ConsoleColor.Yellow);

                Console.WriteLine("- No Recording Software(s) found");
            }

            WriteLine("\nProcess(es) Start Time:\n", ConsoleColor.Yellow); //fatto
            foreach (KeyValuePair<string, string> processStart in RESULTS.processes_starts)
            {
                WriteLine("- " + processStart.Key + processStart.Value);
            }

            WriteLine("\nXray Resource Pack(s):\n", ConsoleColor.Yellow); //fatto
            if (RESULTS.xray_packs.Count > 0)
            {
                RESULTS.xray_packs.ForEach(xray => WriteLine("- " + xray));
            }
            else
            {
                Console.WriteLine("- No Xray resource pack found");
            }

            WriteLine("\nInput Device(s):\n", ConsoleColor.Yellow); //fatto
            if (RESULTS.mouse.Count > 0)
            {
                RESULTS.mouse.ForEach(mouse => WriteLine("- " + mouse));
            }
            else
            {
                Console.WriteLine("- No input devices found");
            }

            WriteLine("\nPcaClient files (no duplicated files):\n", ConsoleColor.Yellow); //fatto
            if (RESULTS.pcaclient.Count > 0)
            {
                RESULTS.pcaclient.Distinct().ToList().ForEach(mouse => WriteLine("- " + mouse));
            }
            else
            {
                Console.WriteLine("- No PcaClient files found");
            }

            #endregion

            #region Write Results (Check 2)

            WriteLine("\nChecks:", ConsoleColor.Red);

            if (RESULTS.Errors.Count > 0) // done
            {
                RESULTS.Errors.Distinct().ToList().ForEach(jna => WriteLine("- " + jna));
            }

            if (RESULTS.possible_replaces.Count > 0) // done
            {
                WriteLine("\nFile's actions file(s):\n", ConsoleColor.Cyan);
                RESULTS.possible_replaces.Sort();
                RESULTS.possible_replaces.Distinct().ToList().ForEach(replace => WriteLine("- " + replace));
            }

            if (RESULTS.event_viewer_entries.Count > 0) // done
            {
                WriteLine("\nBad Eventvwr log(s):\n", ConsoleColor.Cyan);
                RESULTS.event_viewer_entries.Distinct().ToList().ForEach(eventvwr => WriteLine("- " + eventvwr));
            }

            if (RESULTS.suspy_files.Count > 0) // done
            {
                WriteLine("\nGeneric file attributes Check:\n", ConsoleColor.Cyan);
                RESULTS.suspy_files.Sort();
                RESULTS.suspy_files.Distinct().ToList().ForEach(suspy => WriteLine("- " + suspy));
            }
            else
            {
                WriteLine("\nWarning:\n", ConsoleColor.Yellow);
                Console.WriteLine("- No suspicious file found, if user uses \"Kaspersky\" please disable it and rescan");
            }

            if (RESULTS.bypass_methods.Count > 0) // done
            {
                WriteLine("\nBypass methods:\n", ConsoleColor.Cyan);
                RESULTS.bypass_methods.Distinct().ToList().ForEach(replace => WriteLine("- " + replace));
            }

            if (RESULTS.string_scan.Count > 0) // done
            {
                WriteLine("\nString Scan:\n", ConsoleColor.Cyan);
                RESULTS.string_scan.Distinct().ToList().ForEach(strscn => WriteLine("- " + strscn));
            }

            #endregion

            #region Nothing Found
            if (RESULTS.possible_replaces.Count == 0 && RESULTS.suspy_files.Count == 0
                 && RESULTS.event_viewer_entries.Count == 0
                 && RESULTS.string_scan.Count == 0 && RESULTS.bypass_methods.Count == 0)
            {
                WriteLine("\nNothing Found", ConsoleColor.Green);
            }
        }
        #endregion

        #endregion
    }
}