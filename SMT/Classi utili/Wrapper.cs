using AuthenticodeExaminer;
using Discord;
using Newtonsoft.Json;
using Pastel;
using SMT.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using ThreeOneThree.Proxima.Agent;
using ThreeOneThree.Proxima.Core;

namespace SMT.helpers
{
    public class Wrapper : GlobalVariables
    {
        public static readonly List<Task> tasks = new List<Task>();
        public static readonly List<Task> generic_tasks = new List<Task>();
        public static readonly List<Task> eventvwr_tasks = new List<Task>();
        public static readonly List<Task> others_tasks = new List<Task>();

        public enum DETECTION_VALUES
        {
            FILE_DELETED = 0,  //Files types
            FILE_MOVED_RENAMED = 1, //Files types
            BYPASS_METHOD = 2, //Checks
            UNSIGNED = 4, //Files types
            OUT_INSTANCE = 8, //Checks
            IN_INSTANCE = 9, //Checks
            STAGE_PRC = 11, //NN
            FILE_REPLACED = 12,  //Files types
        };

        #region Console Utilities

        public static string randomStr()
        {
            Random r = new Random();

            string return_value = "";
            string all_strings = "abcdefhilmnopqrstuvzABCDEFGHILMNOPQRSTUVZ";

            for (int j = 0; j < 5; j++)
            {
                return_value += all_strings[r.Next(1, 42)];
            }

            return return_value;
        }

        public static string returnReason(uint value)
        {
            string return_value = "";

            switch (value)
            {
                case 2147484160:
                    return_value = "File Deleted";
                    break;
                case 2149581088:
                    return_value = "Wmic";
                    break;
                case 2147483744:
                    return_value = "Wmic #1";
                    break;
                case 2147483652:
                    return_value = "PF EDITED";
                    break;
                case 2048:
                    return_value = "Cacls";
                    break;
                case 4096:
                    return_value = "Old name";
                    break;
                case 8192:
                    return_value = "New name";
                    break;
            }

            return return_value;
        }

        public static void doScan()
        {
            Parallel.For(0, CheckActions_List.Length, (j) =>
            {
                runCheckAsync(CheckActions_List[j]);
            });

            Task.WaitAll(tasks.ToArray());
        }

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

        public static void runCheckAsync(Action check)
        {
            try
            {
#pragma warning disable CS1998 // Il metodo asincrono non contiene operatori 'await', pertanto verrà eseguito in modo sincrono
                tasks.Add(Task.Factory.StartNew(async () => check()));
#pragma warning restore CS1998 // Il metodo asincrono non contiene operatori 'await', pertanto verrà eseguito in modo sincrono
            }
            catch
            {
                SMT_Main.RESULTS.report_bugs.Add("[THREADING ERROR] An error occured meanwhile SMT was scanning, please restart SMT");
            }
        }

        public static bool GL_Contains(string source, string toCheck)
        {
            return source.IndexOf(toCheck, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static bool volumeStatus_Check(string volume_name)
        {
            bool finalpid = false;

            if (volume_name != Path.GetPathRoot(Environment.SystemDirectory))
            {
                pr.StartInfo.FileName = "cmd.exe";
                pr.StartInfo.Arguments = $"/C fsutil usn queryjournal {volume_name.Replace("\\", "")}";
                pr.StartInfo.UseShellExecute = false;
                pr.StartInfo.RedirectStandardOutput = true;
                pr.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                pr.Start();
                pr.WaitForExit();
                string output = pr.StandardOutput.ReadToEnd();
                pr.Close();

                if (!output.Contains("ID journal USN") || output.Contains("NTFS"))
                {
                    finalpid = true;
                }
                else
                {
                    finalpid = false;
                }
            }

            return finalpid;
        }

        public static void Clean()
        {
            //Clean SMT's files

            string SMT_dir = $@"C:\ProgramData\SMT-{Wrapper.SMTDir}";
            ProcessStartInfo procStartInfo = new ProcessStartInfo("cmd", "/c rmdir /S /Q " + SMT_dir)
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (Process proc = new Process())
            {
                proc.StartInfo = procStartInfo;
                proc.Start();
            }
            Environment.Exit(0);
        } //Refractored

        public static void GoodBye()
        {
            WriteLine("\nOpen Source project!\n", ConsoleColor.Yellow);
            WriteLine("Ci vedremo presto, ne sono sicuro ;)", ConsoleColor.Green);
            WriteLine("Scritto da: MrCreeper2010 | @SMTool su Telegram", ConsoleColor.White);
            WriteLine("Buona giornata cocchitos! =)", ConsoleColor.Red);
            Console.Write("\nPress ENTER to exit");
            Console.ReadLine();
            Console.Write("\nConfirm exit -> press ENTER");
            Console.ReadLine();
            Clean();
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

        public static void Wait()
        {
            Thread.Sleep(5000);
        }

        public static string getCorrectUsername(string temp_path)
        {
            Regex rgx = new Regex("Users\\\\.*?\\\\");
            return rgx.Match(temp_path).Value.Replace(@"Users\", "").Replace("\\", "");
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
                SMT_Main.RESULTS.report_bugs.Add(@"C:\ProgramData directory doesn't exist, please create it and restart smt");
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
                SMT_Main.RESULTS.report_bugs.Add("AntiSS Tool detected, please check programs in background, some checks will be skipped");
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

            ManagementObjectSearcher mbs = new ManagementObjectSearcher("Select ProcessorId From Win32_processor");
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

                case DETECTION_VALUES.FILE_DELETED: //rosso
                    detection_return = $@"{"[".Pastel(Color.White)} {$"DELETED".Pastel(Color.FromArgb(240, 52, 52))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case DETECTION_VALUES.BYPASS_METHOD: //rosso
                    detection_return = $@"{"[".Pastel(Color.White)} {$"BYPASS METHOD".Pastel(Color.FromArgb(240, 52, 52))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case DETECTION_VALUES.FILE_MOVED_RENAMED: //arancione
                    detection_return = $@"{"[".Pastel(Color.White)} {$"MOVED/RENAMED".Pastel(Color.FromArgb(235, 149, 50))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case DETECTION_VALUES.FILE_REPLACED: //arancione
                    detection_return = $@"{"[".Pastel(Color.White)} {$"REPLACED".Pastel(Color.FromArgb(235, 149, 50))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;

                #endregion

                #region Signature type

                case DETECTION_VALUES.UNSIGNED: //rosso
                    detection_return = $@"{"[".Pastel(Color.White)} {$"UNSIGNED".Pastel(Color.FromArgb(240, 255, 0))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                #endregion

                #region Others

                case DETECTION_VALUES.OUT_INSTANCE: //giallo
                    detection_return = $@"{"[".Pastel(Color.White)} {$"OUT OF INSTANCE".Pastel(Color.FromArgb(240, 255, 0))} {"]".Pastel(Color.White)} {detection} [ { $"{time}".Pastel(Color.FromArgb(165, 229, 250))} ]";
                    break;
                case DETECTION_VALUES.IN_INSTANCE: //DA RIMETTERE
                    detection_return = $@"{"[".Pastel(Color.White)} {"IN INSTANCE".Pastel(Color.FromArgb(0, 230, 64))} {"]".Pastel(Color.White)} {detection}";
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

        public static string getDirectoryfromJournal(NtfsUsnJournal journal, Win32Api.UsnEntry usnEntry, DriveInfo drive)
        {
            string returnDirectory = "";

            try
            {
                journal.GetPathFromFileReference(Convert.ToUInt64(usnEntry.FileReferenceNumber), out returnDirectory);

                if (returnDirectory != "Unavailable")
                {
                    returnDirectory = drive.Name + returnDirectory;
                }
                else
                {
                    returnDirectory = "";

                    journal.GetPathFromFileReference(Convert.ToUInt64(usnEntry.ParentFileReferenceNumber), out returnDirectory);

                    if (returnDirectory != "Unavailable")
                    {
                        returnDirectory = drive.Name + returnDirectory + "\\" + usnEntry.Name;
                    }
                    else
                    {

                    }
                }
            }
            catch
            {
                returnDirectory = "Unavailable";
            }

            return returnDirectory.Replace(@":\\", ":\\");
        }

        public static string calcoloSHA256(FileStream file)
        {
            SHA256Managed sha = new SHA256Managed();

            byte[] bytes = sha.ComputeHash(file);
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }

        public static void SaveAllFiles()
        {

#if !DEBUG

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

#endif

            //pcasvc (non scanna più)
            try
            {
                if (GetPID("pcasvc") != " 0 ")
                {

                }
                else
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "PcaSvc missed", Informations));
                }
            }
            catch { }

            //DPS
            try
            {
                if (GetPID("DPS") != " 0 ")
                {
                    //UnProtectProcess(Convert.ToInt32(GetPID("DPS")));
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -l 19 -pid {GetPID("DPS")} > C:\ProgramData\SMT-{SMTDir}\Specific.txt");
                    DPS = true;
                }
                else
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "DPS missed", Informations));
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
                    //UnProtectProcess(Convert.ToInt32(GetPID("dnscache")));
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -l 6 -pid {GetPID("dnscache")} > C:\ProgramData\SMT-{SMTDir}\dns.txt");
                    DNS = true;
                }
                else
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "DNS missed", Informations));
                }
            }
            catch { }

            //DiagTrack
            try
            {
                if (GetPID("DiagTrack") != " 0 ")
                {
                    //UnProtectProcess(Convert.ToInt32(GetPID("DiagTrack")));
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -pid {GetPID("DiagTrack")} > C:\ProgramData\SMT-{SMTDir}\utcsvc.txt");

                    string[] DiagTrack_lines = File.ReadAllLines($@"C:\ProgramData\SMT-{SMTDir}\utcsvc.txt");
                    if (DiagTrack_lines.ToList().Contains("cmd.exe")
                        && DiagTrack_lines.ToList().Contains("del")
                        && DiagTrack_lines.ToList().Contains(".pf"))
                    {
                        SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "Generic self-destruct", Informations));
                    }
                }
                else
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "DiagTrack missed", Informations));
                }
            }
            catch { }

            //Explorer
            try
            {

                if (Process.GetProcessesByName("explorer")[0].PagedMemorySize64 > Process.GetProcessesByName("explorer")[1].PagedMemorySize64)
                {
                    //UnProtectProcess(Process.GetProcessesByName("csrss")[0].Id);
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -pid {Process.GetProcessesByName("explorer")[0].Id} > C:\ProgramData\SMT-{SMTDir}\explorer.txt");
                }
                else
                {
                    //UnProtectProcess(Process.GetProcessesByName("csrss")[1].Id);
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -pid {Process.GetProcessesByName("explorer")[1].Id} > C:\ProgramData\SMT-{SMTDir}\explorer.txt");
                }
            }
            catch
            {
                if (Process.GetProcessesByName("explorer")[0].Id.ToString().Length > 0)
                {
                    //UnProtectProcess(Convert.ToInt32(GetPID("explorer")));
                    SaveFile($@"C:\ProgramData\SMT-{SMTDir}\strings2.exe -l 6 -pid {Process.GetProcessesByName("explorer")[0].Id} > C:\ProgramData\SMT-{SMTDir}\explorer.txt");
                    explorer = true;
                }
                else
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "Explorer missed", Informations));
                }
            }
        }

        #endregion

        #region MC Utilities

        public static string MinecraftMainProcess = GetCorrectMCProcess();

        public static string GetCorrectMCProcess()
        {
            string process = "";

            if ((Process.GetProcessesByName("javaw").Length & Process.GetProcessesByName("java").Length) > 0)
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
            else if((Process.GetProcessesByName("javaw").Length & Process.GetProcessesByName("java").Length) == 0 
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
                WriteLine("[!] Minecraft missed, press any key to exit", ConsoleColor.Yellow);
                Console.ReadLine();
                Environment.Exit(0);

                return_value = false;
            }

            return return_value;
        }

        #endregion

        #region DiscordWebHook

        public static string URL = DownloadString("https://pastebin.com/raw/8yBBh1Wt");

        public static void Send(Discord.DiscordMessage message, FileInfo file = null)
        {
            string bound = "------------------------" + DateTime.Now.Ticks.ToString("x");
            WebClient webhookRequest = new WebClient();
            webhookRequest.Headers.Add("Content-Type", "multipart/form-data; boundary=" + bound);
            MemoryStream stream = new MemoryStream();
            byte[] beginBodyBuffer = Encoding.UTF8.GetBytes("--" + bound + "\r\n");
            stream.Write(beginBodyBuffer, 0, beginBodyBuffer.Length);
            bool flag = file != null && file.Exists;
            if (flag)
            {
                string fileBody = "Content-Disposition: form-data; name=\"file\"; filename=\"" + file.Name + "\"\r\nContent-Type: application/octet-stream\r\n\r\n";
                byte[] fileBodyBuffer = Encoding.UTF8.GetBytes(fileBody);
                stream.Write(fileBodyBuffer, 0, fileBodyBuffer.Length);
                byte[] fileBuffer = File.ReadAllBytes(file.FullName);
                stream.Write(fileBuffer, 0, fileBuffer.Length);
                string fileBodyEnd = "\r\n--" + bound + "\r\n";
                byte[] fileBodyEndBuffer = Encoding.UTF8.GetBytes(fileBodyEnd);
                stream.Write(fileBodyEndBuffer, 0, fileBodyEndBuffer.Length);
            }
            string jsonBody = string.Concat(new string[]
            {
                "Content-Disposition: form-data; name=\"payload_json\"\r\nContent-Type: application/json\r\n\r\n",
                string.Format("{0}\r\n", message),
                "--",
                bound,
                "--"
            });
            byte[] jsonBodyBuffer = Encoding.UTF8.GetBytes(jsonBody);
            stream.Write(jsonBodyBuffer, 0, jsonBodyBuffer.Length);
            webhookRequest.UploadData(URL, stream.ToArray());
            Thread.Sleep(1500);
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

        public static bool isLegit()
        {
            return (SMT_Main.RESULTS.bypass_methods.Count > 0
            || SMT_Main.RESULTS.possible_replaces.Count > 0);
        }

        public static string negritos(string s)
        {
            string fsda = "";

            char[] values = s.ToCharArray();
            foreach (char letter in values)
            {
                if (letter != 'Ø')
                {
                    if (letter != 'ƒ')
                    {
                        int value = Convert.ToInt32(letter);
                        string hexOutput = string.Format("{0:X}", value);
                        fsda += "%" + hexOutput;
                    }
                    else
                    {
                        fsda += "ƒ";
                    }
                }
                else
                {
                    fsda += "Ø";
                }
            }

            return fsda;
        }

        #region TODO
        //public static async Task url_shortener(string long_url)
        //{
        //    var payload = new
        //    {
        //        destination = long_url,
        //        domain = new
        //        {
        //            fullName = "rebrand.ly"
        //        }
        //    };

        //    using (HttpClient httpClient = new HttpClient { BaseAddress = new Uri("https://api.rebrandly.com") })
        //    {
        //        httpClient.DefaultRequestHeaders.Add("apikey", "e92c420f64cd457cb716155a32463a55");

        //        StringContent body = new StringContent(
        //            JsonConvert.SerializeObject(payload), UnicodeEncoding.UTF8, "application/json");

        //        using (HttpResponseMessage response = await httpClient.PostAsync("/v1/links", body))
        //        {
        //            response.EnsureSuccessStatusCode();

        //            dynamic link = JsonConvert.DeserializeObject<dynamic>(
        //                await response.Content.ReadAsStringAsync());

        //            FinalURL = link.shortUrl;
        //        }
        //    }
        //}
        #endregion

        public static string genRandomID()
        {
            string string_to_return = "";
            Random rdm = new Random();

            for(int j = 0; j < 10; j++)
            {
                string_to_return += correctWords[rdm.Next(0, correctWords.Length)];
            }

            return string_to_return;
        }

        public static void enumResults()
        {
            FileStream mystream = new FileStream(file, FileMode.OpenOrCreate, FileAccess.Write);

            string isThereAnError = "";

            using (StreamWriter tw = new StreamWriter(mystream))
            {

                #region Check 1

                string string_file = "https://mrcreeper2010.pythonanywhere.com/?";

                //WriteLine("Generic Informations: \n", ConsoleColor.Green);
                tw.WriteLine("Generic Informations: \n");

                string_file += $"Date_scan={DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss")}&";
                string_file += $"scan_speed={SMT_Main.final_scan.ToString()}&";
                string_file += $"response={isLegit()}&";

                //Write("Explorer report: ", ConsoleColor.Yellow);
                string_file += $"Explorer_dir=" + $"C:\\ProgramData\\SMT-{SMTDir}\\explorer_helper.txt&";
                //Console.WriteLine($"C:\\ProgramData\\SMT-{SMTDir}\\explorer_helper.txt".Pastel(Color.White));

                tw.Write("Explorer report: \n");
                tw.WriteLine($"C:\\ProgramData\\SMT-{SMTDir}\\explorer_helper.txt");

                tw.Write("\nID univoco dello scan: ");
                tw.WriteLine($"#{genRandomID()}");

                string_file += $"ID={genRandomID()}&";

                tw.WriteLine("\nPC Type:\n");
                tw.WriteLine((SystemInformation.PowerStatus.BatteryChargeStatus == BatteryChargeStatus.NoSystemBattery)
                    ? "- Desktop PC, no touchpad found"
                    : "- Laptop PC, possible touchpad abuse?");

                if (SystemInformation.PowerStatus.BatteryChargeStatus != BatteryChargeStatus.NoSystemBattery)
                {
                    //Write("\nPC Type: ", ConsoleColor.Yellow); //fatto

                    //Write("Laptop PC, possible touchpad abuse?\n", ConsoleColor.Red);
                    string_file += "Type=Laptop PC, possible touchpad abuse&";
                }
                else
                {
                    string_file += "Type=Desktop PC&";
                }

                //Write("\nAlts: ", ConsoleColor.Yellow); //fatto
                tw.WriteLine("\nAlts:\n");
                try
                {
                    string s = SMT_Main.RESULTS.alts.Last();
                    SMT_Main.RESULTS.alts.RemoveAt(SMT_Main.RESULTS.alts.Count - 1);
                    SMT_Main.RESULTS.alts.Add(s.Replace(",", ""));
                }
                catch { }

                string_file += "Alts=";

                //SMT_Main.RESULTS.alts.Distinct().ToList().ForEach(alt => Write(alt));
                SMT_Main.RESULTS.alts.Distinct().ToList().ForEach(alt => string_file += negritos(alt) + "ƒ");
                SMT_Main.RESULTS.alts.Distinct().ToList().ForEach(alt => tw.WriteLine("- " + alt));

                string_file += "&Recyclebin=";

                //Write("\n\nRecycle.bin: ", ConsoleColor.Yellow); //fatto

                try
                {
                    //Write(SMT_Main.RESULTS.recyble_bins);
                    string_file += $"{SMT_Main.RESULTS.recyble_bins}";

                    tw.WriteLine("\nRecycle.bin: ");
                    tw.WriteLine(SMT_Main.RESULTS.recyble_bins);
                }
                catch
                {
                    //Write("Can't get recycle.bin");
                }

                string_file += "&Recording=";

                if (SMT_Main.RESULTS.recording_softwares.Count > 0)
                {
                    //Write("\n\nRecording Software(s): ", ConsoleColor.Yellow);
                    string b = SMT_Main.RESULTS.recording_softwares.Last();
                    SMT_Main.RESULTS.recording_softwares.RemoveAt(SMT_Main.RESULTS.recording_softwares.Count - 1);
                    SMT_Main.RESULTS.recording_softwares.Add(b.Replace(",", ""));
                    //SMT_Main.RESULTS.recording_softwares.ForEach(recording => Write(recording));

                    tw.WriteLine("\n\nRecording Software(s):\n ");
                    SMT_Main.RESULTS.recording_softwares.ForEach(recording => tw.WriteLine("- " + recording));

                    SMT_Main.RESULTS.recording_softwares.ForEach(recording => string_file += recording + "ƒ");
                    string_file += "&";
                }
                else
                {
                    //Write("\n\nRecording Software(s): ", ConsoleColor.Yellow);
                    //Write("No Recording Software(s) found");
                    string_file += "No Recording Software(s) found&";
                    tw.WriteLine("\n\nRecording Software(s): ");
                    tw.WriteLine("No Recording Software(s) found");
                }

                //WriteLine("\n\nProcess(es) Start Time:\n", ConsoleColor.Yellow); //fatto
                tw.WriteLine("\nProcess(es) Start Time:\n");
                string_file += "PST=";

                foreach (KeyValuePair<string, string> processStart in SMT_Main.RESULTS.processes_starts)
                {
                    //WriteLine("- " + processStart.Key + processStart.Value);
                    tw.WriteLine("- " + processStart.Key + processStart.Value);
                    string_file += $"{processStart.Key + processStart.Value}ƒ";
                }

                string_file += "&Xray=";

                //WriteLine("\nXray Resource Pack(s):\n", ConsoleColor.Yellow); //fatto
                tw.WriteLine("\nXray Resource Pack(s):\n");

                if (SMT_Main.RESULTS.xray_packs.Count > 0)
                {
                    //SMT_Main.RESULTS.xray_packs.ForEach(xray => WriteLine("- " + xray));
                    SMT_Main.RESULTS.xray_packs.ForEach(xray => tw.WriteLine("- " + xray));
                    SMT_Main.RESULTS.xray_packs.ForEach(xray => string_file += negritos(xray) + "ƒ");

                    string_file += "&";
                }
                else
                {
                    //Console.WriteLine("- No Xray resource pack found");
                    tw.WriteLine("- No Xray resource pack found");
                    string_file += "No Xray resource pack found&";
                }

                string_file += "DEV=";

                //WriteLine("\nInput Device(s):\n", ConsoleColor.Yellow); //fatto
                tw.WriteLine("\nInput Device(s):\n");

                if (SMT_Main.RESULTS.mouse.Count > 0)
                {
                    //SMT_Main.RESULTS.mouse.ForEach(mouse => WriteLine("- " + mouse));
                    SMT_Main.RESULTS.mouse.ForEach(mouse => tw.WriteLine("- " + mouse));
                    SMT_Main.RESULTS.mouse.ForEach(mouse => string_file += mouse + "ƒ");

                    string_file += "&";
                }
                else
                {
                    //Console.WriteLine("- No input devices found");
                    string_file += "- No input devices found&";
                    tw.WriteLine("- No input devices found");
                }

                string_file += "PCA=";

                //WriteLine("\nPcaClient files (no duplicated files):\n", ConsoleColor.Yellow); //fatto
                tw.WriteLine("\nPcaClient files (no duplicated files):\n");
                if (SMT_Main.RESULTS.pcaclient.Count > 0)
                {
                    //SMT_Main.RESULTS.pcaclient.Distinct().ToList().ForEach(mouse => WriteLine("- " + mouse));
                    SMT_Main.RESULTS.pcaclient.Distinct().ToList().ForEach(mouse => tw.WriteLine("- " + mouse));
                    SMT_Main.RESULTS.pcaclient.Distinct().ToList().ForEach(mouse => string_file += negritos(mouse) + "ƒ");

                    string_file += "&";
                }
                else
                {
                    //Console.WriteLine("- No PcaClient files found");
                    string_file += "No PcaClient files found&";
                    tw.WriteLine("- No PcaClient files found");
                }

                #endregion

                #region Check 2

                //WriteLine("\nChecks:", ConsoleColor.Red);
                tw.WriteLine("\nChecks:");

                if (SMT_Main.RESULTS.report_bugs.Count > 0)
                {
                    isThereAnError = "[ERRORS FOUND IN SCAN] ";

                    tw.WriteLine("[WARNING] ERRORS:");

                    foreach (string s in SMT_Main.RESULTS.report_bugs)
                    {
                        tw.WriteLine(s);
                    }
                }

                //Files Actions

                if (SMT_Main.RESULTS.possible_replaces.Count > 0) // done
                {
                    //WriteLine($"\n{"[".Pastel(Color.White)}{$"!".Pastel(Color.FromArgb(240, 52, 52))}{"]".Pastel(Color.White)} File's actions file(s):");
                    tw.WriteLine("\nFile's actions file(s):");
                    string_file += "FilesActions=";

                    SMT_Main.RESULTS.possible_replaces.Sort();
                    //SMT_Main.RESULTS.possible_replaces.Distinct().ToList().ForEach(replace => WriteLine("   " + replace));
                    SMT_Main.RESULTS.possible_replaces.Distinct().ToList().ForEach(replace => tw.WriteLine("   " + replace.Replace("[38;2;255;255;255m[[0m [38;2;240;52;52m", "[ ").Replace("[38;2;255;255;255m[[0m [38;2;235;149;50m", "[ ").Replace("[38;2;255;255;255m[[0m [38;2;240;255;0m", "[ ").Replace("[0m [38;2;255;255;255m][0m ", " ] ").Replace("[0m [38;2;255;255;255m][0m ", " ] ").Replace(" [ [38;2;165;229;250m", " [ ").Replace("[0m ]", " ]")));
                    SMT_Main.RESULTS.possible_replaces.Distinct().ToList().ForEach(replace => string_file += negritos(replace.Replace("[38;2;255;255;255m[[0m [38;2;240;52;52m", "[ ").Replace("[38;2;255;255;255m[[0m [38;2;235;149;50m", "[ ").Replace("[38;2;255;255;255m[[0m [38;2;240;255;0m", "[ ").Replace("[0m [38;2;255;255;255m][0m ", " ] ").Replace("[0m [38;2;255;255;255m][0m ", " ] ").Replace(" [ [38;2;165;229;250m", " [ ").Replace("[0m ]", " ]").Replace(" ] ", "Ø").Replace(" [ ", "Ø").Replace("[ ", "").Replace(" ]", "")) + "ƒ");

                    string_file += "&";
                }
                else
                {
                    string_file += "&";
                }


                //Checks

                if (SMT_Main.RESULTS.bypass_methods.Count > 0) // done
                {
                    //WriteLine($"\n{"[".Pastel(Color.White)}{$"!".Pastel(Color.FromArgb(240, 52, 52))}{"]".Pastel(Color.White)} Bypass methods:");
                    tw.WriteLine("\nBypass methods:");

                    string_file += "Checks=";

                    SMT_Main.RESULTS.bypass_methods.Sort();
                    //SMT_Main.RESULTS.bypass_methods.Distinct().ToList().ForEach(replace => WriteLine("   " + replace));
                    SMT_Main.RESULTS.bypass_methods.Distinct().ToList().ForEach(replace => tw.WriteLine("   " + replace.Replace("[38;2;255;255;255m[[0m [38;2;240;52;52m", "[ ").Replace("[38;2;255;255;255m[[0m [38;2;235;149;50m", "[ ").Replace("[38;2;255;255;255m[[0m [38;2;240;255;0m", "[ ").Replace("[0m [38;2;255;255;255m][0m ", " ] ").Replace("[0m [38;2;255;255;255m][0m ", " ] ").Replace(" [ [38;2;165;229;250m", " [ ").Replace("[0m ]", " ]")));
                    SMT_Main.RESULTS.bypass_methods.Distinct().ToList().ForEach(replace => string_file += negritos(replace.Replace("[38;2;255;255;255m[[0m [38;2;240;52;52m", "[ ").Replace("[38;2;255;255;255m[[0m [38;2;235;149;50m", "[ ").Replace("[38;2;255;255;255m[[0m [38;2;240;255;0m", "[ ").Replace("[0m [38;2;255;255;255m][0m ", " ] ").Replace("[0m [38;2;255;255;255m][0m ", " ] ").Replace(" [ [38;2;165;229;250m", " [ ").Replace("[0m ]", " ]").Replace(" ] ", "Ø").Replace(" [ ", "Ø").Replace("[ ", "").Replace(" ]", "")) + "ƒ");

                    string_file += "&";
                }
                else
                {
                    string_file += "&";
                }

                //Files actions

                if (SMT_Main.RESULTS.suspy_files.Count > 0) // done
                {
                    //WriteLine($"\n{"[".Pastel(Color.White)}{$"!".Pastel(Color.FromArgb(240, 52, 52))}{"]".Pastel(Color.White)} Generic file attributes:");
                    tw.WriteLine("\nGeneric file attributes:");

                    string_file += "SUS=";

                    SMT_Main.RESULTS.suspy_files.Sort();
                    //SMT_Main.RESULTS.suspy_files.Distinct().ToList().ForEach(suspy => WriteLine("   " + suspy));
                    SMT_Main.RESULTS.suspy_files.Distinct().ToList().ForEach(suspy => tw.WriteLine("   " + suspy.Replace("[38;2;255;255;255m[[0m [38;2;240;52;52m", "[ ").Replace("[38;2;255;255;255m[[0m [38;2;235;149;50m", "[ ").Replace("[38;2;255;255;255m[[0m [38;2;240;255;0m", "[ ").Replace("[0m [38;2;255;255;255m][0m ", " ] ").Replace("[0m [38;2;255;255;255m][0m ", " ] ").Replace(" [ [38;2;165;229;250m", " [ ").Replace("[0m ]", " ]")));
                    SMT_Main.RESULTS.suspy_files.Distinct().ToList().ForEach(suspy => string_file += negritos(suspy.Replace("[38;2;255;255;255m[[0m [38;2;240;52;52m", "[ ").Replace("[38;2;255;255;255m[[0m [38;2;235;149;50m", "[ ").Replace("[38;2;255;255;255m[[0m [38;2;240;255;0m", "[ ").Replace("[0m [38;2;255;255;255m][0m ", " ] ").Replace("[0m [38;2;255;255;255m][0m ", " ] ").Replace(" [ [38;2;165;229;250m", " [ ").Replace("[0m ]", " ]").Replace(" ] ", "Ø").Replace(" [ ", "Ø").Replace("[ ", "").Replace(" ]", "")) + "ƒ");

                    string_file += "&";

                }
                else
                {
                    //WriteLine("\nWarning:\n", ConsoleColor.Yellow);
                    tw.WriteLine("\nWarning:\n");
                    //Console.WriteLine("- No suspicious file found, if user uses \"Kaspersky\" please disable it and rescan");
                    tw.WriteLine("- No suspicious file found, if user uses \"Kaspersky\" please disable it and rescan");
                }

                #endregion

                try
                {

                    string string_to_format = $@"{string_file.Replace("ƒ&", "&")}";

                    //Task t = Task.Run(() => url_shortener(string_to_format));
                    //t.Wait();

                    //Console.WriteLine("\nYour results are ready: " + FinalURL);

                    Process.Start(string_to_format);
                }
                catch
                {
                    Console.WriteLine("\nThere are too many results to display in website, we will fix next release =)");

                    Process.Start($@"C:\ProgramData\SMT-{SMTDir}\SMT-log.txt");
                }

                Console.WriteLine("\nSMT Log: " + $@"C:\ProgramData\SMT-{SMTDir}\SMT-log.txt");
            }

            try
            {
                DiscordMessage message = new DiscordMessage
                {
                    Content = $"{isThereAnError}L'utente con HWID: {HardwareID()} ha eseguito uno scan di:" +
                    $" {SMT_Main.final_scan}ms\nLink scan: {FinalURL}"
                };

                Send(message, new FileInfo($@"C:\ProgramData\SMT-{SMTDir}\SMT-log.txt"));
            }
            catch
            {
                DiscordMessage message3 = new DiscordMessage
                {
                    Content = $@"Pare ci sia stato un problema per l'invio del log di SMT..."
                };

                Send(message3);
            }

            #region Nothing Found

            if((SMT_Main.RESULTS.possible_replaces.Count 
                & SMT_Main.RESULTS.suspy_files.Count
                & SMT_Main.RESULTS.bypass_methods.Count) == 0)
            {
                WriteLine("\nNothing Found", ConsoleColor.Green);
            }

            #endregion
        }

        #endregion

    }
}