using Discord;
using Ionic.Zip;
using Microsoft.Win32;
using SMT.helpers;
using SMT.Helpers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using ThreeOneThree.Proxima.Agent;
using ThreeOneThree.Proxima.Core;

namespace SMT.scanners
{
    public class Checks : Wrapper
    {
        public void HeuristicCsrssCheck()
        {
            GlobalVariables globalVariables = new GlobalVariables();

            Regex regex_path = new Regex(@"[A-Z]:\\.*?$");
            string[] CSRSS_file = File.ReadAllLines($@"C:\ProgramData\SMT-{SMTDir}\csrss.txt");

            Parallel.ForEach(CSRSS_file, (index) =>
            {
                if (index.Contains(".")
                && index.Contains(Path.GetPathRoot(Environment.SystemDirectory))
                    && Path.GetExtension(index).Length > 0
                    && suspy_extension.Contains(Path.GetExtension(index.ToUpper()))
                    && !GL_Contains(index, ".dll"))
                {
                    Match Csrss_path = regex_path.Match(index);

                    if (Csrss_path.Success
                    && prefetchfiles.Where(x => x
                    .Contains(Path.GetFileName(Csrss_path.Value).ToUpper()))
                    .FirstOrDefault() != null
                    && prefetchfiles
                    .Where(f => File.GetLastWriteTime(Csrss_path.Value)
                    >= PC_StartTime())
                    .FirstOrDefault() != null)
                    {
                        switch (GetSign(Csrss_path.Value))
                        {
                            case "Unsigned":
                                if (!GL_Contains(Csrss_path.Value, "windows"))
                                {
                                    if (!GL_Contains(Csrss_path.Value, "strings2.exe")
                                    && calcoloSHA256(new FileStream(Csrss_path.Value, FileMode.Open))
                                    != "736f66305b85b1ff01b735491db3fae966815ba9ae830c3fec1ab750430f5cdf")
                                        SMT_Main.RESULTS.suspy_files.Add(Detection(DETECTION_VALUES.UNSIGNED, Csrss_path.Value, "This file hasn't got any digital signature, please investigate"));
                                }
                                break;
                            case "Fake":
                                if (!GL_Contains(Csrss_path.Value, "unprotect.exe")
                                && calcoloSHA256(new FileStream(Csrss_path.Value, FileMode.Open))
                                != "7c8b131c5222b69ccfd6664fb9c7d93b071e7f377d1fe8b224cf6ea4367a379f")
                                    SMT_Main.RESULTS.suspy_files.Add(Detection(DETECTION_VALUES.FAKE_SIGN, Csrss_path.Value, "File has got a fake/expired digital signature"));
                                break;
                            case "Other type of signature":
                                SMT_Main.RESULTS.suspy_files.Add(Detection(DETECTION_VALUES.UNKN_SIGN, Csrss_path.Value, "Suspicious digital signature's informations, please investigate"));
                                break;
                        }
                    }
                }
            });

            SMT_Main.RESULTS.suspy_files.Sort();

            Console.WriteLine(Detection(DETECTION_VALUES.STAGE_PRC, "", "Suspicious file check completed"));
        } //Refractored

        public static void StringScannerSystem(string link, char separator, string result)
        {
            //StringScanner system by GabTeix (https://github.com/GabTeix) (project removed)
            string file_lines = "";

            file_lines = File.ReadAllText(result, Encoding.Default);

            WebClient client = new WebClient();
            string cheat, client_str;

            List<string> clientsdetected = new List<string>();
            ManagementClass mngmtClass = new ManagementClass("Win32_Process");

            Regex get_initialstring = new Regex(".*?/");
            Regex remove_junkdps_strings2 = new Regex("\\.exe!.*?/");
            Regex due_puntiescl = new Regex("!!");
            Regex regular_string = new Regex("!!.*?!");
            Regex remove_junk1 = new Regex("!");
            Regex DPS_WMIC = new Regex(@".*?:");

            foreach (ManagementObject o in mngmtClass.GetInstances())
            {
                if (Process.GetProcessesByName(Wrapper.MinecraftMainProcess).Length > 0)
                {
                    if (o["Name"].Equals(Wrapper.MinecraftMainProcess))
                    {
                        if (o["CommandLine"].ToString().Contains(@"11.15.1.1722"))
                        {
                            can_scan = false;
                            break;
                        }
                    }
                }
            }

            Dictionary<string, string> javaw_strings = new Dictionary<string, string>();
            string streamReader_line;

            using (Stream stream = client.OpenRead(link))
            {
                using (BufferedStream bs = new BufferedStream(stream))
                {
                    using (StreamReader streamReader = new StreamReader(bs))
                    {
                        while ((streamReader_line = streamReader.ReadLine()) != null)
                        {
                            client_str = streamReader_line.Split(new char[]
                                {
                                    separator
                                })[0];
                            cheat = streamReader_line.Split(new char[]
                            {
                                   separator
                            })[1];

                            //DPS
                            if (link == "https://pastebin.com/raw/adJN0gu4"
                                && file_lines.ToLower().Contains(client_str))
                            {
                                string[] file_lines2 = File.ReadAllLines(result);
                                string cheat_filename = "";

                                Parallel.ForEach(file_lines2, (index) =>
                                {
                                    if (index.Contains(client_str))
                                    {
                                        Match mch = get_initialstring.Match(index);
                                        int count = mch.Value.Count(f => f == '!');

                                        if (count == 3)
                                        {
                                            //!! -> ! -> !!ciao.exe!
                                            Match regular = regular_string.Match(index);

                                            //!!
                                            cheat_filename = due_puntiescl.Replace(regular.Value, "");

                                            //!
                                            cheat_filename = remove_junk1.Replace(cheat_filename, "");

                                            for (int j = 0; j < Wrapper.prefetchfiles.Count; j++)
                                            {
                                                if (Wrapper.prefetchfiles[j].Contains(cheat_filename.ToUpper())
                                                && File.GetLastWriteTime(Wrapper.prefetchfiles[j]) >= Wrapper.PC_StartTime())
                                                {
                                                    SMT_Main.RESULTS.string_scan.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.OUT_INSTANCE, cheat, "File: " + cheat_filename));
                                                }
                                            }
                                        }
                                        else if (count > 3)
                                        {

                                            SMT_Main.RESULTS.string_scan.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.OUT_INSTANCE, cheat, "User tried to bypass this check adding a lot of !"));
                                        }
                                    }
                                });
                            }
                            else if (link == "https://pastebin.com/raw/adJN0gu4")
                            {
                                string[] DPS_file_lines = File.ReadAllLines($@"C:\ProgramData\SMT-{Wrapper.SMTDir}\Specific.txt");
                                Regex get_wmic_regex = new Regex(".*?/");

                                Parallel.ForEach(DPS_file_lines, (index) =>
                                {
                                    if (index.Contains("!")
                                    && index.Contains(":")
                                    && index.Contains("/"))
                                    {
                                        Match mch = get_wmic_regex.Match(index);

                                        if (mch.Success
                                        && mch.Value.Contains(":"))
                                        {
                                            //DPS
                                            SMT_Main.RESULTS.bypass_methods.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.WMIC, mch.Value, "Wmic started today or few days ago, please investigate #1"));
                                        }
                                    }
                                });
                            }
                            //DNS o lsass
                            else if (link == "https://pastebin.com/raw/1LKLuNWh"
                                && file_lines.ToLower().Contains(client_str))
                            {
                                SMT_Main.RESULTS.string_scan.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.OUT_INSTANCE, cheat, "(User isn't necessarily cheating)"));
                            }
                            //else if (link == "https://pastebin.com/raw/uu6excEE"
                            //    && can_scan
                            //    && result.Contains(client_str)
                            //    && !cheat.Contains("Found Generic"))
                            //{
                            //    SMT.SMT_Main.RESULTS.string_scan.Add(Wrapper.Detection("In Instance", cheat, "No more informations"));
                            //}
                        }
                    }
                }
            }

            Parallel.ForEach(javaw_strings, keyValuePair =>
            {
                if (result.Contains(keyValuePair.Key)
                && link == "https://pastebin.com/raw/uu6excEE")
                {
                    SMT_Main.RESULTS.string_scan.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.IN_INSTANCE, keyValuePair.Value, "No more informations"));
                }
            });


            for (int j = 0; j < clientsdetected.Count; j++)
            {
                SMT_Main.RESULTS.string_scan.Add(clientsdetected[j]);
            }
        } //Refractored

        public void EventVwrCheck()
        {
            #region Variabili

            string bytes = "";

            string LogSource = "Microsoft-Windows-User Device Registration/Admin";
            string sQuery = "*[System/EventID=360]";

            string StorageSpaces = "Microsoft-Windows-StorageSpaces-Driver/Operational";
            string bQuery = "*[System/EventID=207]";

            #endregion

            #region Cambio ora, logs del security eliminati, journal eliminato 

            eventvwr_tasks.Add(Task.Run(() =>
            {
                List<EventLogEntry> Security_entries = GetSecurity_log.Entries.Cast<EventLogEntry>().ToList();
                List<EventLogEntry> System_entries = GetSystem_log.Entries.Cast<EventLogEntry>().ToList();
                List<EventLogEntry> Application_entries = GetApplication_log.Entries.Cast<EventLogEntry>().ToList();

                Parallel.ForEach(Security_entries, (index) =>
                {
                    if (PC_StartTime() <= index.TimeGenerated)
                    {
                        if (index.InstanceId == 1102)
                        {
                            SMT_Main.RESULTS.bypass_methods.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.BYPASS_METHOD, "Security logs deleted", "No more informations"));
                        }
                    }
                });

                Parallel.ForEach(System_entries, (Security) =>
                {
                    if (PC_StartTime() <= Security.TimeGenerated)
                    {
                        if (Security.InstanceId == 104)
                        {
                            SMT_Main.RESULTS.bypass_methods.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.BYPASS_METHOD, "\"Security\" logs deleted", "No more informations"));
                        }
                        else if (Security.EventID == 7031)
                        {
                            foreach (byte single_bytes in Security.Data)
                            {
                                bytes += single_bytes;
                            }
                        }
                    }
                });

                Parallel.ForEach(Application_entries, (Application_log) =>
                {
#pragma warning disable CS0618 // Il tipo o il membro è obsoleto
                    if (Application_log.EventID == 3079 && Wrapper.PC_StartTime() <= Application_log.TimeGenerated)
                    {
#pragma warning restore CS0618 // Il tipo o il membro è obsoleto
                        SMT_Main.RESULTS.bypass_methods.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.BYPASS_METHOD, "USN Journal was deleted", Application_log.TimeGenerated.ToString()));
                    }
                });

            }));

            #endregion

            #region Cambio ora preciso check

            eventvwr_tasks.Add(Task.Run(() =>
            {

                EventRecord entry;
                string logPath = @"C:\Windows\System32\winevt\Logs\Security.evtx";
                EventLogReader logReader = new EventLogReader(logPath, PathType.FilePath);

                while ((entry = logReader.ReadEvent()) != null)
                {
                    if (entry.Id != 4616)
                    {
                        continue;
                    }

                    if (entry.TimeCreated <= Wrapper.PC_StartTime())
                    {
                        continue;
                    }

                    IList<EventProperty> properties = entry.Properties;
                    DateTime previousTime = DateTime.Parse(properties[4].Value.ToString());
                    DateTime newTime = DateTime.Parse(properties[5].Value.ToString());

                    if (Math.Abs((previousTime - newTime).TotalMinutes) > 5)
                    {
                        SMT_Main.RESULTS.bypass_methods.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.BYPASS_METHOD, "System time change", $"Old -> {previousTime} New -> {newTime}"));
                    }
                }

            }));

            #endregion

            #region Riavvio Explorer || DPS || Pcasvc || DiagTrack

            eventvwr_tasks.Add(Task.Run(() =>
            {

                EventLogQuery elQuery = new EventLogQuery(LogSource, PathType.LogName, sQuery);

                using (EventLogReader elReader = new EventLogReader(elQuery))
                {
                    for (EventRecord dodo = elReader.ReadEvent(); dodo != null; dodo = elReader.ReadEvent())
                    {
                        if (Wrapper.MinecraftMainProcess != "" && dodo.TimeCreated >= Process.GetProcessesByName(Wrapper.MinecraftMainProcess)[0].StartTime)
                        {
                            SMT_Main.RESULTS.bypass_methods.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.BYPASS_METHOD, "Explorer was restarted after Minecraft", dodo.TimeCreated.ToString()));
                        }
                    }
                }
            }));

            #endregion

            #region Uso di USB

            eventvwr_tasks.Add(Task.Run(() =>
            {

                EventLogQuery rQuery = new EventLogQuery(StorageSpaces, PathType.LogName, bQuery);
                using (EventLogReader elReader = new EventLogReader(rQuery))
                {
                    for (EventRecord dodo = elReader.ReadEvent(); dodo != null; dodo = elReader.ReadEvent())
                    {
                        DateTime UpdatedTime = (DateTime)dodo.TimeCreated;

                        if (dodo.TimeCreated > PC_StartTime()
                        && UpdatedTime.AddMinutes(-5) > PC_StartTime())
                        {
                            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD,
                                "Volume/USB connected", dodo.TimeCreated.ToString()));
                        }
                    }
                }

            }));

            #endregion

            Task.WaitAll(eventvwr_tasks.ToArray());

            switch (bytes)
            {
                case "68080083000":
                    SMT_Main.RESULTS.bypass_methods.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.BYPASS_METHOD, "DPS was restarted", "No more informations"));
                    break;
                case "800990970830118099000":
                    SMT_Main.RESULTS.bypass_methods.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.BYPASS_METHOD, "PcaSvc", "No more informations"));
                    break;
                case "680105097010308401140970990107000":
                    SMT_Main.RESULTS.bypass_methods.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.BYPASS_METHOD, "DiagTrack was restarted", "No more informations"));
                    break;
                case "830121011507709701050110000":
                    SMT_Main.RESULTS.bypass_methods.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.BYPASS_METHOD, "Prefetch was disabled (Sysmain restarted)", "No more informations"));
                    break;
            }

            Console.WriteLine(Wrapper.Detection(Wrapper.DETECTION_VALUES.STAGE_PRC, "", "Eventvwr check completed"));
        } //Refractored

        public void OtherChecks()
        {
            Console.OutputEncoding = Encoding.Unicode;
            List<string> journal_names = new List<string>();
            List<string> tda = new List<string>();
            bool unicode_char = false;

            #region Metodo da riprendere

            /*
            others_tasks.Add(Task.Run(() =>
            {
                Parallel.ForEach(Process.GetProcesses(), (single_process) =>
                {
                    try
                    {
                        var processFileName = Path.GetFileName(single_process.MainModule.FileName).ToUpper();

                        if (GetSign(single_process.MainModule.FileName) != "Signed"
                        && single_process.MainModule.FileName != Assembly.GetExecutingAssembly().Location
                        && prefetchfiles.Where(x => x.Contains(processFileName)) != null
                        && prefetchfiles.Where(f => File.GetLastWriteTime(processFileName)
                        >= PC_StartTime()) != null)
                        {
                            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $"Unsigned process is in background", $"Process's name: {single_process.MainModule.FileName}"));
                        }

                    }
                    catch
                    {

                    }
                });
            }));
            */

            #endregion

            others_tasks.Add(Task.Run(() =>
            {
                Dictionary<int, string> check_for_recycle = new Dictionary<int, string>();

                #region Wmic da regedit

                string regedit_replace = "";
                Regex DiscoC = new Regex(@"\\Device\\HarddiskVolume4\\");
                Regex remove_stream = new Regex(@":.*?$");
                Regex jessica = new Regex(@".*?$");

                using (RegistryKey get_subkeynames = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"))
                {
                    Parallel.ForEach(get_subkeynames.GetSubKeyNames(), (subkey_name) =>
                    {
                        using (RegistryKey correct_key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\" + subkey_name))
                        {
                            if (!check_for_recycle.ContainsKey(correct_key.GetValueNames().Count()) && !check_for_recycle.ContainsValue(subkey_name))
                                check_for_recycle.Add(correct_key.GetValueNames().Count(), subkey_name);

                            foreach (string values in correct_key.GetValueNames())
                            {
                                if (values.Contains(":")
                                    && values.Contains(@"\Device\HarddiskVolume4\"))
                                {
                                    Match mch = jessica.Match(values);
                                    regedit_replace = DiscoC.Replace(mch.Value, $"{Path.GetPathRoot(Environment.SystemDirectory)}");

                                    SMT_Main.RESULTS.bypass_methods.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.WMIC, regedit_replace, "Wmic started today or few days ago, please investigate #2"));
                                }
                                else if (values.Contains(":")
                                    && !values.Contains(@"\Device\HarddiskVolume4\"))
                                {
                                    SMT_Main.RESULTS.bypass_methods.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.WMIC, values, "Wmic started today or few days ago, please investigate #2"));
                                }
                            }
                        }
                    });
                }

                var sortedDict = from entry in check_for_recycle orderby entry.Key ascending select entry;

                SMT_Main.RESULTS.recyble_bins = File.GetLastWriteTime($@"C:\$Recycle.bin\{sortedDict.ElementAt(sortedDict.Count() - 1).Value}").ToString();

                #endregion
            }));

            others_tasks.Add(Task.Run(() =>
            {

                #region Disabilitazione del Prefetch #1 e #2

                RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters");

                if (key.GetValue("EnablePrefetcher").ToString() != "3")
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.BYPASS_METHOD, "Prefetch was disabled", "No more informations"));
                }

                if (Wrapper.GetPID("SysMain") == " 0 ")
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.BYPASS_METHOD, "Prefetch was disabled", "No more informations"));
                }

                #endregion
            }));

            others_tasks.Add(Task.Run(() =>
            {
                #region Check delle macro

                if (Directory.Exists($@"C:\Users\{username}\AppData\Local\LGHUB\")
                && (File.GetLastWriteTime($@"C:\Users\{username}\AppData\Local\LGHUB\settings.backup") >= Process.GetProcessesByName(MinecraftMainProcess)[0].StartTime
                || File.GetLastWriteTime($@"C:\Users\{username}\AppData\Local\LGHUB\settings.json") >= Process.GetProcessesByName(MinecraftMainProcess)[0].StartTime))
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $@"Logitech macro detected!", "(BETA Method)"));
                }
                else if (Directory.Exists($@"C:\Users\{username}\AppData\Local\BY-COMBO2\")
                    && (File.GetLastWriteTime($@"C:\Users\{username}\AppData\Local\BY-COMBO2\pro.dct") >= Process.GetProcessesByName(MinecraftMainProcess)[0].StartTime
                    || File.GetLastWriteTime($@"C:\Users\{username}\AppData\Local\BY-COMBO2\curid.dct") >= Process.GetProcessesByName(MinecraftMainProcess)[0].StartTime))
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $@"Glorious macro detected!", "(BETA Method)"));
                }


                #endregion
            }));

            others_tasks.Add(Task.Run(() =>
            {

                #region Check unlegit versions

                var default_mc_path = $@"C:\Users\{username}\AppData\Roaming\.minecraft\versions";
                var version_Directories = Directory.GetDirectories(default_mc_path);
                int inUsingFile = 0;

                WebClient wb = new WebClient();
                var s = wb.DownloadString("https://pastebin.com/raw/vrcAF3dq");

                ManagementClass mngmtClass = new ManagementClass("Win32_Process");
                Regex getversion = new Regex("--version.*?--gameDir");

                foreach (ManagementObject o in mngmtClass.GetInstances())
                {
                    if (o["Name"].ToString() == Wrapper.MinecraftMainProcess + ".exe")
                    {
                        var sda = getversion.Match(o["CommandLine"].ToString());

                        if (sda.Success)
                        {
                            var version = sda.Value.Replace("--version ", "").Replace(" --gameDir", "");

                            var jar_file = default_mc_path + "\\" + version + "\\" + version + ".jar";

                            if (IsFileLocked(new FileInfo(jar_file)))
                            {
                                inUsingFile++;

                                if (!GL_Contains(s, calcoloSHA256(new FileStream(jar_file, FileMode.Open))))
                                {
                                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $"Modified version found: {Path.GetFileName(jar_file)}", "No more Informations"));
                                }
                            }
                        }
                        else
                        {
                            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $"Impossible to get {o["Name"]}'s (PID: {int.Parse(o["Handle"].ToString())}) informations", "No more Informations"));
                        }
                    }
                }

                if (inUsingFile > 1)
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "More than 1 version is used", "(BETA Method)"));
                }
                else if (inUsingFile == 0)
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "No versions used in .minecraft, is it possible?", "(BETA Method)"));
                }

                #endregion

            }));

            others_tasks.Add(Task.Run(() =>
            {
                Parallel.ForEach(prefetchfiles, (d) =>
                {
                    try
                    {
                        using (FileStream fs = new FileStream(d, FileMode.Open))
                        {
                            bool da = fs.CanWrite;
                        }
                    }
                    catch (UnauthorizedAccessException e)
                    {
                        SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $"{d} got readonly permission to bypass LAV and other tools", "No more Informations"));
                    }
                });
            }));

            others_tasks.Add(Task.Run(() =>
            {

                #region PcaClient e MountVol

                var get_PCACLIENT = File.ReadAllLines($@"C:\ProgramData\SMT-{SMTDir}\explorer.txt");
                StreamWriter sl = File.CreateText($@"C:\ProgramData\SMT-{SMTDir}\explorer_helper.txt");
                List<string> to_distinct = new List<string>();
                sl.Close();

                Regex correctPath = new Regex("[A-Z]:\\\\.*?,");

                Parallel.ForEach(get_PCACLIENT, (index) =>
                {
                    if (index.Contains("file://")
                    && !index.Contains("\"backgroundColor\"")
                        && !index.Contains("\"displayText\"")
                        && !GL_Contains(index, "visited: ")
                        && index.Length >= 14
                        && !GL_Contains(index, $": {Wrapper.username}@file:///")
                        && !index.Contains("?")
                        && !GL_Contains(index, "\""))
                    {
                        int count = index.Replace("file:///", "").Count(f => f == ':');

                        if (count == 1)
                        {
                            if (!GL_Contains(index, "."))
                                to_distinct.Add("[VISITED FOLDER] " + index.Replace("file:///", "").Replace("%20", " "));
                            else if (GL_Contains(index, "."))
                                to_distinct.Add(index.Replace("file:///", "").Replace("%20", " "));
                        }
                    }

                    if (GL_Contains(index, "pcaclient")
                    && GL_Contains(index, "trace")
                    && index.Length > 27)
                    {
                        var path = correctPath.Match(index);

                        if (path.Success && path.Value.Length > 0)
                        {
                            string d = path.Value;
                            d = d.Remove(d.Length - 1, 1) + "";

                            SMT_Main.RESULTS.pcaclient.Add(d);
                        }
                    }
                    else if (GL_Contains(index, @"\\?\volume{")
                    && GL_Contains(index, "-")
                    && index.Length >= 50)
                    {
                        var volume = mountvol_Method.Match(index);

                        if (volume.Success && volume.Value.Length > 0)
                        {
                            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "Possible basic mountvol method found", "(BETA Method)"));
                        }
                    }

                });

                FileStream mystream = new FileStream($@"C:\ProgramData\SMT-{SMTDir}\explorer_helper.txt",
                    FileMode.OpenOrCreate, FileAccess.Write);
                StreamWriter tw = new StreamWriter(mystream);

                to_distinct.Sort();
                var sas = to_distinct.Distinct().ToList();

                foreach (string n in sas)
                {
                    tw.WriteLine(n);
                }
                tw.Close();

                long file_size = new System.IO.FileInfo($@"C:\ProgramData\SMT-{SMTDir}\explorer_helper.txt").Length;

                try
                {
                    DiscordMessage message = new DiscordMessage
                    {
                        Content = $@"Report dell'explorer dell'utente con HWID: {HardwareID()}"
                    };

                    Send(message, new FileInfo($@"C:\ProgramData\SMT-{SMTDir}\explorer_helper.txt"));

                }
                catch
                {

                }

                if (file_size == 0)
                {
                    SMT_Main.RESULTS.Errors.Add("Explorer file is empty, this error is automatically reported to developer =)");
                }

                #endregion

            }));

            #region Metodo carattere speciale + Regedit aperto + Java/Javaw

            Parallel.ForEach(prefetchfiles, (index) =>
            {
                unicode_char = ContainsUnicodeCharacter(index);

                if (File.GetLastWriteTime(index) >= PC_StartTime())
                {
                    if (File.GetLastWriteTime(index) >= Process.GetProcessesByName(Wrapper.MinecraftMainProcess)[0].StartTime)
                    {
                        if (unicode_char)
                        {
                            SMT_Main.RESULTS.bypass_methods.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.BYPASS_METHOD, "Special char found", index));
                        }
                        else if (Wrapper.GL_Contains(index, "regedit.exe"))
                        {
                            SMT_Main.RESULTS.bypass_methods.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.BYPASS_METHOD, "Regedit opened after Minecraft, please investigate", File.GetLastWriteTime(index).ToString()));
                        }
                        else if (Wrapper.GL_Contains(index, "regsvc32.exe"))
                        {
                            SMT_Main.RESULTS.bypass_methods.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.BYPASS_METHOD, "Regsvc32 used after Minecraft, please investigate", File.GetLastWriteTime(index).ToString()));
                        }
                    }

                    if (Wrapper.GL_Contains(index, "java.exe"))
                    {
                        foreach (var s in Prefetch.PrefetchFile.Open(index).Filenames)
                        {
                            var volume = javajar_method.Match(s);

                            if (volume.Success && volume.Value.Length > 0)
                            {
                                string trytoget_disk = s.Replace(volume.Value, Path.GetPathRoot(Environment.SystemDirectory));

                                if (!journal_names.Contains(trytoget_disk))
                                    journal_names.Add(trytoget_disk);

                                Random r = new Random();

                                if (File.Exists(trytoget_disk))
                                {
                                    try
                                    {
                                        using (ZipFile targetZipFile = ZipFile.Read(trytoget_disk))
                                        {
                                            foreach (var zipItem in targetZipFile)
                                            {
                                                if (GL_Contains(zipItem.ToString(), "meta-inf"))
                                                {
                                                    var dir = $@"{Path.GetTempPath()}\SMT-{r.Next(1000, 9999)}-{randomStr()}";
                                                    Directory.CreateDirectory(dir);

                                                    zipItem.Extract(dir);

                                                    using (StreamReader sr = new StreamReader($@"{dir}\META-INF\MANIFEST.MF"))
                                                    {
                                                        var f = File.ReadAllText($@"{dir}\META-INF\MANIFEST.MF");

                                                        if (GL_Contains(f, "main-class"))
                                                        {
                                                            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $"Possible Java -jar found on: {trytoget_disk.Replace(@"\\", "\\")}", "No more Informations"));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    catch
                                    {

                                    }
                                }
                            }
                        }
                    }
                }
            });

            #endregion

            #region Check Journal

            int cacls_counter = 0;

            Win32Api.USN_JOURNAL_DATA data = new Win32Api.USN_JOURNAL_DATA();

            foreach (DriveInfo drive in drives)
            {
                if (drive.IsReady && !GL_Contains(drive.DriveFormat, "fat32"))
                {
                    if (volumeStatus_Check(drive.Name))
                        SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $"USN Journal isn't active for {drive.Name} volume", $"No more Informations"));

                    DriveConstruct construct = new DriveConstruct(drive.Name);
                    NtfsUsnJournal journal = new NtfsUsnJournal(drive.Name);

                    NtfsUsnJournal.UsnJournalReturnCode rtn = journal.GetUsnJournalEntries(construct.CurrentJournalData, reasonMask, out List<Win32Api.UsnEntry> usnEntries, out Win32Api.USN_JOURNAL_DATA newUsnState, OverrideLastUsn: data.MaxUsn);

                    List<string> cacls_string = new List<string>();

                    if (rtn == NtfsUsnJournal.UsnJournalReturnCode.USN_JOURNAL_SUCCESS)
                    {
                        Parallel.ForEach(usnEntries, (d) =>
                        {
                            if (TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp) >= PC_StartTime())
                            {
                                if (d.IsFile)
                                {
                                    var getPath = getDirectoryfromJournal(journal, d, drive);

                                    if (GL_Contains(d.Name, "ConsoleHost_history.txt"))
                                    {
                                        var s = getDirectoryfromJournal(journal, d, drive);

                                        if ((d.Reason == 4096 || d.Reason == 2147484160) && !GL_Contains(s, "Unavailable") && s.Contains($@"C:\Users\{Wrapper.username}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"))
                                        {
                                            SMT_Main.RESULTS.possible_replaces.Add(Detection(DETECTION_VALUES.FILE_MOVED_RENAMED, "Powershell history was deleted/removed/renamed", $"File renamed after Minecraft {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                        }
                                    }

                                    if (GL_Contains(d.Name, ".lnk"))
                                    {
                                        var s = getDirectoryfromJournal(journal, d, drive);
                                        var path = Environment.GetFolderPath(Environment.SpecialFolder.Recent);

                                        if (!GL_Contains(s, "Unavailable") && s.Contains(path)
                                        && GL_Contains(d.Name, ".pf"))
                                        {
                                            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $"PF file was edited", $"File name: {Path.GetFileName(d.Name)}"));
                                        }
                                    }

                                    if (returnReason(d.Reason).Length > 0)
                                    {
                                        foreach (var f in journal_names)
                                        {
                                            if (GL_Contains(f, d.Name) && d.Reason == 2147484160)
                                            {
                                                if (TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)
                                                        >= Process.GetProcessesByName(MinecraftMainProcess)[0].StartTime)
                                                    SMT_Main.RESULTS.possible_replaces.Add(Detection(DETECTION_VALUES.FILE_DELETED, "From JAVA.exe Prefetch's log: " + d.Name, $"File deleted after Minecraft {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                            }
                                        }

                                        if (d.Reason == 2149581088)
                                        {
                                            if (!GL_Contains(getPath, "Unavailable"))
                                                SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.WMIC, getPath, $"Wmic method started today at {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                            else if (GL_Contains(getPath, "Unavailable"))
                                                SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.WMIC, d.Name + " on: " + drive.Name + " volume", $"Wmic method started today at {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                        }
                                        else if (suspy_extension.Contains(Path.GetExtension(d.Name.ToUpper())) && TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp) >= Process.GetProcessesByName(Wrapper.MinecraftMainProcess)[0].StartTime)
                                        {
                                            if (!GL_Contains(d.Name, "jnativehook") && !GL_Contains(Path.GetExtension(d.Name), ".dll"))
                                            {
                                                switch (d.Reason)
                                                {
                                                    case 4096:
                                                        if (!GL_Contains(getPath, "Unavailable"))
                                                            SMT_Main.RESULTS.possible_replaces.Add(Detection(DETECTION_VALUES.FILE_MOVED_RENAMED, getPath, $"File renamed after Minecraft {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                                        else if (GL_Contains(getPath, "Unavailable"))
                                                            SMT_Main.RESULTS.possible_replaces.Add(Detection(DETECTION_VALUES.FILE_MOVED_RENAMED, d.Name + " on: " + drive.Name + " volume", $"File renamed after Minecraft {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                                        break;
                                                    case 2147484160:
                                                        if (File.Exists(getPath))
                                                        {
                                                            if (!GL_Contains(getPath, "Unavailable"))
                                                                SMT_Main.RESULTS.possible_replaces.Add(Detection(DETECTION_VALUES.FILE_REPLACED, getPath, $"File was replaced after Minecraft {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                                            else if (GL_Contains(getPath, "Unavailable"))
                                                                SMT_Main.RESULTS.possible_replaces.Add(Detection(DETECTION_VALUES.FILE_REPLACED, d.Name + " on: " + drive.Name + " volume", $"File was replaced after Minecraft {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                                        }
                                                        else
                                                        {
                                                            if (!GL_Contains(getPath, "Unavailable"))
                                                                SMT_Main.RESULTS.possible_replaces.Add(Detection(DETECTION_VALUES.FILE_DELETED, getPath, $"File was deleted after Minecraft {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                                            else if (GL_Contains(getPath, "Unavailable"))
                                                                SMT_Main.RESULTS.possible_replaces.Add(Detection(DETECTION_VALUES.FILE_DELETED, d.Name + " on: " + drive.Name + " volume", $"File was deleted after Minecraft {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                                        }
                                                        break;
                                                }
                                            }
                                            else if (GL_Contains(d.Name, "jnativehook") && GL_Contains(Path.GetExtension(d.Name), ".dll"))
                                            {
                                                SMT_Main.RESULTS.string_scan.Add(Detection(DETECTION_VALUES.OUT_INSTANCE, "Generic JNativeHook Clicker (deleted)", TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp).ToString()));
                                            }
                                        }
                                    }
                                }

                                if (returnReason(d.Reason).Length > 0)
                                {
                                    if (d.IsFolder && d.Reason == 2048 && d.Name == "Prefetch" && !cacls_string.Contains(TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp).ToString()))
                                    {
                                        cacls_string.Add(TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp).ToString());

                                        cacls_counter++;
                                    }
                                }
                            }
                        });
                    }
                    else
                    {
                        SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $"Impossible to get informations from {drive.Name}", $"No more Informations"));
                    }
                }
                else
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $"USN Journal isn't active for {drive.Name} volume", $"No more Informations"));
                }
            }

            Parallel.For(0, GetTemp_files.Count, (index) =>
            {
                if (GetTemp_files[index].Contains("JNATIVEHOOK")
                    && File.GetLastWriteTime(GetTemp_files[index])
                    >= Process.GetProcessesByName(Wrapper.MinecraftMainProcess)[0].StartTime)
                {
                    SMT_Main.RESULTS.string_scan.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.OUT_INSTANCE, "Generic JNativeHook Clicker", File.GetLastWriteTime(Wrapper.GetTemp_files[index]).ToString()));
                }
            });

            if (File.GetLastWriteTime($@"C:\Users\{username}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine") >= Process.GetProcessesByName(MinecraftMainProcess)[0].StartTime)
            {
                SMT_Main.RESULTS.string_scan.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.BYPASS_METHOD, "Powershell history modified or command issued after Minecraft ran", File.GetLastWriteTime($@"C:\Users\{username}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine").ToString()));
            }

            if (cacls_counter >= 3)
            {
                SMT_Main.RESULTS.possible_replaces.Add(Wrapper.Detection(Wrapper.DETECTION_VALUES.BYPASS_METHOD, "Cacls method started today", "No more informations"));
            }

            Console.WriteLine(Wrapper.Detection(Wrapper.DETECTION_VALUES.STAGE_PRC, "", "USNJournal check completed"));

            #endregion

            Task.WaitAll(others_tasks.ToArray());

            Console.WriteLine(Wrapper.Detection(Wrapper.DETECTION_VALUES.STAGE_PRC, "", "Other checks completed"));
        } //Refractored

        public void DoStringScan()
        {
            List<Task> tasks = new List<Task>();

            Task DPS = new Task(delegate { StringScannerSystem("https://pastebin.com/raw/adJN0gu4", '§', $@"C:\ProgramData\SMT-{Wrapper.SMTDir}\Specific.txt"); });
            DPS.Start(); tasks.Add(DPS);

            Task LSASS = new Task(delegate { StringScannerSystem("https://pastebin.com/raw/1LKLuNWh", '§', $@"C:\ProgramData\SMT-{Wrapper.SMTDir}\Browser.txt"); });
            LSASS.Start(); tasks.Add(LSASS);

            Task DNS = new Task(delegate { StringScannerSystem("https://pastebin.com/raw/1LKLuNWh", '§', $@"C:\ProgramData\SMT-{Wrapper.SMTDir}\dns.txt"); });
            DNS.Start(); tasks.Add(DNS);

            Task.WaitAll(tasks.ToArray());

            Console.WriteLine(Wrapper.Detection(Wrapper.DETECTION_VALUES.STAGE_PRC, "", "Specific client check completed"));
        }
    }
}