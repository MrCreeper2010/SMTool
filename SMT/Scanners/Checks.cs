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
    public class Checks
    {
        public static bool can_scan = true;

        #region EventLog(s) Global Variable(s)
        public EventLog GetSecurity_log = new EventLog("Security");
        public EventLog GetSystem_log = new EventLog("System");
        public EventLog GetApplication_log = new EventLog("Application");
        #endregion

        #region Global List(s)
        public List<string> possible_replaces { get; set; } = new List<string>();
        public List<string> suspy_files { get; set; } = new List<string>();
        public List<string> event_viewer_entries { get; set; } = new List<string>();
        public List<string> string_scan { get; set; } = new List<string>();

        #endregion

        public void HeuristicCsrssCheck()
        {
            GlobalVariables globalVariables = new GlobalVariables();

            Regex regex_path = new Regex(@"[A-Z]:\\.*?$");
            string[] CSRSS_file = File.ReadAllLines($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\csrss.txt");

            Parallel.ForEach(CSRSS_file, (index) =>
            {
                if (index.Contains(".")
                && index.Contains(Path.GetPathRoot(Environment.SystemDirectory))
                    && Path.GetExtension(index).Length > 0
                    && GlobalVariables.suspy_extension.Contains(Path.GetExtension(index.ToUpper()))
                    && !index.ToUpper().Contains(".DLL"))
                {
                    Match Csrss_path = regex_path.Match(index);

                    if (Csrss_path.Success
                    && SMTHelper.prefetchfiles.Where(x => x
                    .Contains(Path.GetFileName(Csrss_path.Value).ToUpper()))
                    .FirstOrDefault() != null
                    && SMTHelper.prefetchfiles
                    .Where(f => File.GetLastWriteTime(Csrss_path.Value)
                    >= SMTHelper.PC_StartTime())
                    .FirstOrDefault() != null)
                    {
                        switch (SMTHelper.GetSign(Csrss_path.Value))
                        {
                            case "Unsigned":
                                if (!Csrss_path.Value.ToUpper().Contains("WINDOWS"))
                                {
                                    SMT.RESULTS.suspy_files.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.UNSIGNED, Csrss_path.Value, "This file hasn't got any digital signature, please investigate"));
                                }
                                break;
                            case "Fake":
                                SMT.RESULTS.suspy_files.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.FAKE_SIGN, Csrss_path.Value, "File has got a fake/expired digital signature"));
                                break;
                            case "Other type of signature":
                                SMT.RESULTS.suspy_files.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.UNKN_SIGN, Csrss_path.Value, "Suspicious digital signature's informations, please investigate"));
                                break;
                        }
                    }
                }
            });

            SMT.RESULTS.suspy_files.Sort();

            Console.WriteLine(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.STAGE_PRC, "", "Suspicious file check completed"));
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
                if (Process.GetProcessesByName(SMTHelper.MinecraftMainProcess).Length > 0)
                {
                    if (o["Name"].Equals(SMTHelper.MinecraftMainProcess))
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

                                            for (int j = 0; j < SMTHelper.prefetchfiles.Count; j++)
                                            {
                                                if (SMTHelper.prefetchfiles[j].Contains(cheat_filename.ToUpper())
                                                && File.GetLastWriteTime(SMTHelper.prefetchfiles[j]) >= SMTHelper.PC_StartTime())
                                                {
                                                    SMT.RESULTS.string_scan.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.OUT_INSTANCE, cheat, "File: " + cheat_filename));
                                                }
                                            }
                                        }
                                        else if (count > 3)
                                        {

                                            SMT.RESULTS.string_scan.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.OUT_INSTANCE, cheat, "User tried to bypass this check adding a lot of !"));
                                        }
                                    }
                                });
                            }
                            else if (link == "https://pastebin.com/raw/adJN0gu4")
                            {
                                string[] DPS_file_lines = File.ReadAllLines($@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\Specific.txt");
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
                                            SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.WMIC, mch.Value, "Wmic started today or few days ago, please investigate #1"));
                                        }
                                    }
                                });
                            }
                            //DNS o lsass
                            else if (link == "https://pastebin.com/raw/1LKLuNWh"
                                && file_lines.ToLower().Contains(client_str))
                            {
                                SMT.RESULTS.string_scan.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.OUT_INSTANCE, cheat, "(User isn't necessarily cheating)"));
                            }
                            //else if (link == "https://pastebin.com/raw/uu6excEE"
                            //    && can_scan
                            //    && result.Contains(client_str)
                            //    && !cheat.Contains("Found Generic"))
                            //{
                            //    SMT.RESULTS.string_scan.Add(SMTHelper.Detection("In Instance", cheat, "No more informations"));
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
                    SMT.RESULTS.string_scan.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.IN_INSTANCE, keyValuePair.Value, "No more informations"));
                }
            });


            for (int j = 0; j < clientsdetected.Count; j++)
            {
                SMT.RESULTS.string_scan.Add(clientsdetected[j]);
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

            List<EventLogEntry> Security_entries = GetSecurity_log.Entries.Cast<EventLogEntry>().ToList();
            List<EventLogEntry> System_entries = GetSystem_log.Entries.Cast<EventLogEntry>().ToList();
            List<EventLogEntry> Application_entries = GetApplication_log.Entries.Cast<EventLogEntry>().ToList();

            Parallel.ForEach(Security_entries, (index) =>
            {
                if (index.InstanceId == 1102 && SMTHelper.PC_StartTime() < index.TimeGenerated)
                {
                    SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, "Security logs deleted", "No more informations"));
                }

            });

            Parallel.ForEach(System_entries, (Security) =>
            {
                if (Security.InstanceId == 104 && SMTHelper.PC_StartTime() <= Security.TimeGenerated)
                {
                    SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, "\"Security\" logs deleted", "No more informations"));
                }

#pragma warning disable CS0618 // Il tipo o il membro è obsoleto
                else if (Security.EventID == 7031 && SMTHelper.PC_StartTime() <= Security.TimeGenerated)
#pragma warning restore CS0618 // Il tipo o il membro è obsoleto
                {
                    foreach (byte single_bytes in Security.Data)
                    {
                        bytes += single_bytes;
                    }
                }
            });

            Parallel.ForEach(Application_entries, (Application_log) =>
            {
#pragma warning disable CS0618 // Il tipo o il membro è obsoleto
                if (Application_log.EventID == 3079 && SMTHelper.PC_StartTime() <= Application_log.TimeGenerated)
                {
#pragma warning restore CS0618 // Il tipo o il membro è obsoleto
                    SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, "USN Journal was deleted", Application_log.TimeGenerated.ToString()));
                }
            });

            #endregion

            #region Cambio ora preciso check

            EventRecord entry;
            string logPath = @"C:\Windows\System32\winevt\Logs\Security.evtx";
            EventLogReader logReader = new EventLogReader(logPath, PathType.FilePath);

            while ((entry = logReader.ReadEvent()) != null)
            {
                if (entry.Id != 4616)
                {
                    continue;
                }

                if (entry.TimeCreated <= SMTHelper.PC_StartTime())
                {
                    continue;
                }

                IList<EventProperty> properties = entry.Properties;
                DateTime previousTime = DateTime.Parse(properties[4].Value.ToString());
                DateTime newTime = DateTime.Parse(properties[5].Value.ToString());

                if (Math.Abs((previousTime - newTime).TotalMinutes) > 5)
                {
                    SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, "System time change", $"Old -> {previousTime} New -> {newTime}"));
                }
            }

            #endregion

            #region Riavvio Explorer || DPS || Pcasvc || DiagTrack

            EventLogQuery elQuery = new EventLogQuery(LogSource, PathType.LogName, sQuery);

            using (EventLogReader elReader = new EventLogReader(elQuery))
            {
                for (EventRecord dodo = elReader.ReadEvent(); dodo != null; dodo = elReader.ReadEvent())
                {
                    if (SMTHelper.MinecraftMainProcess != "" && dodo.TimeCreated >= Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime)
                    {
                        SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, "Explorer was restarted after Minecraft", dodo.TimeCreated.ToString()));
                    }
                }
            }

            /*
             * 830121011507709701050110000 SYSMAIN
             */

            switch (bytes)
            {
                case "68080083000":
                    SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, "DPS was restarted", "No more informations"));
                    break;
                case "800990970830118099000":
                    SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, "PcaSvc", "No more informations"));
                    break;
                case "680105097010308401140970990107000":
                    SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, "DiagTrack was restarted", "No more informations"));
                    break;
                case "830121011507709701050110000":
                    SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, "Prefetch was disabled (Sysmain restarted)", "No more informations"));
                    break;
            }

            #endregion

            #region Uso di USB

            EventLogQuery rQuery = new EventLogQuery(StorageSpaces, PathType.LogName, bQuery);
            using (EventLogReader elReader = new EventLogReader(rQuery))
            {
                for (EventRecord dodo = elReader.ReadEvent(); dodo != null; dodo = elReader.ReadEvent())
                {
                    DateTime UpdatedTime = (DateTime)dodo.TimeCreated;

                    if (dodo.TimeCreated > SMTHelper.PC_StartTime() && UpdatedTime.AddMinutes(-5) > SMTHelper.PC_StartTime())
                    {
                        SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, "USB connected", dodo.TimeCreated.ToString()));
                    }
                }
            }

            #endregion

            Console.WriteLine(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.STAGE_PRC, "", "Eventvwr check completed"));
        } //Refractored

        public static List<string> journal_names = new List<string>();

        public void OtherChecks()
        {
            Console.OutputEncoding = Encoding.Unicode;
            bool unicode_char = false;

            #region Metodo carattere speciale + Regedit aperto + Java/Javaw

            Parallel.ForEach(SMTHelper.prefetchfiles, (index) =>
            {
                unicode_char = SMTHelper.ContainsUnicodeCharacter(index);

                if (File.GetLastWriteTime(index) >= Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime)
                {
                    if (unicode_char)
                    {
                        SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, "Special char found", index));
                    }
                    else if (index.ToUpper().Contains("REGEDIT.EXE")
                        && File.GetLastWriteTime(index) >= Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime)
                    {
                        SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, "Regedit opened after Minecraft, please investigate", File.GetLastWriteTime(index).ToString()));
                    }
                }
            });

            #endregion

            #region Wmic da regedit

            string regedit_replace = "";
            Regex DiscoC = new Regex(@"\\Device\\HarddiskVolume4\\");
            Regex remove_stream = new Regex(@":.*?$");
            Regex jessica = new Regex(@".*?$");

            using (RegistryKey get_subkeynames = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"))
            {
                foreach (string subkey_name in get_subkeynames.GetSubKeyNames())
                {
                    using (RegistryKey correct_key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\" + subkey_name))
                    {
                        foreach (string values in correct_key.GetValueNames())
                        {
                            if (values.Contains(":")
                                && values.Contains(@"\Device\HarddiskVolume4\"))
                            {
                                Match mch = jessica.Match(values);
                                regedit_replace = DiscoC.Replace(mch.Value, "C:\\");

                                SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.WMIC, regedit_replace, "Wmic started today or few days ago, please investigate #2"));
                            }
                            else if (values.Contains(":")
                                && !values.Contains(@"\Device\HarddiskVolume4\"))
                            {
                                SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.WMIC, values, "Wmic started today or few days ago, please investigate #2"));
                            }
                        }
                    }
                }
            }

            #endregion

            #region Disabilitazione del Prefetch #1 e #2 metodo da mettere il 3°

            RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters");

            if (key.GetValue("EnablePrefetcher").ToString() != "3")
            {
                SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, "Prefetch was disabled", "No more informations"));
            }

            if (SMTHelper.GetPID("SysMain") == " 0 ")
            {
                SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, "Prefetch was disabled", "No more informations"));
            }

            #endregion

            #region Check delle macro

            if (Directory.Exists($@"C:\Users\{Environment.UserName}\AppData\Local\LGHUB\")
                && (File.GetLastWriteTime($@"C:\Users\{Environment.UserName}\AppData\Local\LGHUB\settings.backup") >= Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime
                || File.GetLastWriteTime($@"C:\Users\{Environment.UserName}\AppData\Local\LGHUB\settings.json") >= Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime))
            {
                SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, $@"Logitech macro detected!", "(BETA Method)"));
            }
            else if (Directory.Exists($@"C:\Users\{Environment.UserName}\AppData\Local\BY-COMBO2\")
                && (File.GetLastWriteTime($@"C:\Users\{Environment.UserName}\AppData\Local\BY-COMBO2\pro.dct") >= Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime
                || File.GetLastWriteTime($@"C:\Users\{Environment.UserName}\AppData\Local\BY-COMBO2\curid.dct") >= Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime))
            {
                SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, $@"Glorious macro detected!", "(BETA Method)"));
            }


            #endregion

            #region Check unlegit versions

            var version_Directories = Directory.GetDirectories($@"C:\Users\{Environment.UserName}\AppData\Roaming\.minecraft\versions");
            int inUsingFile = 0;

            WebClient wb = new WebClient();
            var s = wb.DownloadString("https://pastebin.com/raw/0kjRrqiC");

            Parallel.ForEach(version_Directories, (index) =>
            {
                var version_File = Directory.GetFiles(index, "*.jar");

                for (int j = 0; j < version_File.Length; j++)
                {
                    if (SMTHelper.IsFileLocked(new FileInfo(version_File[j])))
                    {
                        inUsingFile++;

                        if (!s.Contains(SMTHelper.calcoloSHA256(new FileStream(version_File[j], FileMode.Open))))
                        {
                            SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, "Modified minecraft's version", "No more Informations"));
                        }
                    }
                }
            });

            if (inUsingFile > 1)
            {
                SMT.RESULTS.bypass_methods.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, "More than 1 version is used", "No more Informations"));
            }

            #endregion

            Console.WriteLine(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.STAGE_PRC, "", "Prefetch, regedit, macro checks completed"));
        } //Refractored

        public string returnReason(uint value)
        {
            string return_value = "";

            switch (value)
            {
                case 2147484160:
                    return_value = "File Deleted";
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
                case 2149581088:
                    return_value = "Wmic";
                    break;
            }

            return return_value;
        }

        public void USNJournal()
        {
            #region Reasons
            uint reasonMask =
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
            #endregion

            int cacls_counter = 0;
            int javajar_counter = 0;

            Win32Api.USN_JOURNAL_DATA data = new Win32Api.USN_JOURNAL_DATA();

            DriveConstruct construct = new DriveConstruct(Path.GetPathRoot(Environment.SystemDirectory));
            NtfsUsnJournal journal = new NtfsUsnJournal(Path.GetPathRoot(Environment.SystemDirectory));

            NtfsUsnJournal.UsnJournalReturnCode rtn = journal.GetUsnJournalEntries(construct.CurrentJournalData, reasonMask, out List<Win32Api.UsnEntry> usnEntries, out Win32Api.USN_JOURNAL_DATA newUsnState, OverrideLastUsn: data.MaxUsn);

            List<string> cacls_string = new List<string>();

            if (rtn == NtfsUsnJournal.UsnJournalReturnCode.USN_JOURNAL_SUCCESS)
            {
                Parallel.ForEach(usnEntries, (d) =>
                {
                    if (TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp).ToString("dd/MM/yyyy")
                    == DateTime.Now.ToString("dd/MM/yyyy")
                    && returnReason(d.Reason).Length > 0)
                    {
                        //wmic, eliminati, rinominati e spostati

                        //DA AGGIUSTARE QUESTO FOTTUTO SPAGHETTINO CODE

                        if (d.Reason == 2149581088
                        && TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)
                        >= SMTHelper.PC_StartTime())
                        {
                            SMT.RESULTS.possible_replaces.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.WMIC, d.Name, $"Wmic method started today {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                        }
                        else if (d.Reason == 2048
                        && d.Name == "Prefetch"
                        && d.IsFolder
                        && TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)
                        >= SMTHelper.PC_StartTime()
                        && !cacls_string.Contains(TimeZone.CurrentTimeZone.
                        ToLocalTime(d.TimeStamp).ToString()))
                        {
                            cacls_string.Add(TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp).ToString());
                            cacls_counter++;
                        }
                        else if (d.Reason == 4096
                            && SMTHelper.journal_returnconditions(d)
                            && !d.Name.ToUpper().Contains("JNATIVEHOOK")
                            && Path.GetExtension(d.Name.ToUpper()) != ".DLL")
                        {
                            SMT.RESULTS.possible_replaces.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.FILE_MOVED_RENAMED, d.Name, $"File renamed after Minecraft {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                        }
                        else if (SMTHelper.journal_returnconditions(d)
                            && !d.Name.ToUpper().Contains("JNATIVEHOOK")
                            && Path.GetExtension(d.Name.ToUpper()) != ".DLL")
                        {
                            SMT.RESULTS.possible_replaces.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.FILE_DELETED, d.Name, $"File deleted after Minecraft {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                        }
                        else if (SMTHelper.journal_returnconditions(d)
                        && d.Name.ToUpper().Contains("JNATIVEHOOK")
                        && Path.GetExtension(d.Name.ToUpper()) == ".DLL")
                        {
                            SMT.RESULTS.string_scan.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.OUT_INSTANCE, "Generic JNativeHook Clicker (deleted)", TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp).ToString()));
                        }
                    }

                });
            }
            else
            {
                SMT.RESULTS.Errors.Add("USNJournal unreachable" + rtn.ToString());
                throw new UsnJournalException(rtn);
            }

            Parallel.For(0, SMTHelper.GetTemp_files.Count, (index) =>
            {
                if (SMTHelper.GetTemp_files[index].Contains("JNATIVEHOOK")
                    && File.GetLastWriteTime(SMTHelper.GetTemp_files[index])
                    >= Process.GetProcessesByName(SMTHelper.MinecraftMainProcess)[0].StartTime)
                {
                    SMT.RESULTS.string_scan.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.OUT_INSTANCE, "Generic JNativeHook Clicker", File.GetLastWriteTime(SMTHelper.GetTemp_files[index]).ToString()));
                }
            });

            if (cacls_counter >= 3)
            {
                SMT.RESULTS.possible_replaces.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, "Cacls method started today", "No more informations"));
            }

            //JAVA -JAR NON FUNZIONANTE

            if (javajar_counter >= 2)
            {
                SMT.RESULTS.possible_replaces.Add(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.BYPASS_METHOD, "Java -jar method started today", "(ALFA Method)"));
            }

            Console.WriteLine(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.STAGE_PRC, "", "USNJournal check completed"));
        }

        public void DoStringScan()
        {
            List<Task> tasks = new List<Task>();

            Task DPS = new Task(delegate { StringScannerSystem("https://pastebin.com/raw/adJN0gu4", '§', $@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\Specific.txt"); });
            DPS.Start(); tasks.Add(DPS);

            Task LSASS = new Task(delegate { StringScannerSystem("https://pastebin.com/raw/1LKLuNWh", '§', $@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\Browser.txt"); });
            LSASS.Start(); tasks.Add(LSASS);

            Task DNS = new Task(delegate { StringScannerSystem("https://pastebin.com/raw/1LKLuNWh", '§', $@"C:\ProgramData\SMT-{SMTHelper.SMTDir}\dns.txt"); });
            DNS.Start(); tasks.Add(DNS);

            Parallel.ForEach(tasks, index =>
            {
                index.Wait();
            });

            Console.WriteLine(SMTHelper.Detection(SMTHelper.DETECTION_VALUES.STAGE_PRC, "", "Specific client check completed"));
        }
    }
}