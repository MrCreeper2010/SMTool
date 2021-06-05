using Discord;
using Ionic.Zip;
using Microsoft.Win32;
using SMT.helpers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using ThreeOneThree.Proxima.Agent;
using ThreeOneThree.Proxima.Core;

namespace SMT.scanners
{
    public class Checks : Wrapper
    {
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
                if (Process.GetProcessesByName(MinecraftMainProcess).Length > 0)
                {
                    if (o["Name"].Equals(MinecraftMainProcess))
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

                                            for (int j = 0; j < prefetchfiles.Count; j++)
                                            {
                                                if (prefetchfiles[j].Contains(cheat_filename.ToUpper())
                                                && File.GetLastWriteTime(prefetchfiles[j]) >= PC_StartTime())
                                                {
                                                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.OUT_INSTANCE, cheat, "File: " + cheat_filename));
                                                }
                                            }
                                        }
                                        else if (count > 3)
                                        {

                                            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.OUT_INSTANCE, cheat, "User tried to bypass this check adding a lot of !"));
                                        }
                                    }
                                });
                            }
                            else if (link == "https://pastebin.com/raw/adJN0gu4")
                            {
                                string[] DPS_file_lines = File.ReadAllLines($@"C:\ProgramData\SMT-{SMTDir}\Specific.txt");
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
                                            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, mch.Value, "Wmic started few days ago #1"));
                                        }
                                    }
                                });
                            }
                            //DNS o lsass
                            else if (link == "https://pastebin.com/raw/1LKLuNWh"
                                && file_lines.ToLower().Contains(client_str))
                            {
                                SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.OUT_INSTANCE, cheat, "(User isn't necessarily cheating)"));
                            }

                            #region In Instance

                            //else if (link == "https://pastebin.com/raw/uu6excEE"
                            //    && can_scan
                            //    && result.Contains(client_str)
                            //    && !cheat.Contains("Found Generic"))
                            //{
                            //    SMT.SMT_Main.RESULTS.bypass_methods.Add(Detection("In Instance", cheat, Informations));
                            //}

                            #endregion
                        }
                    }
                }
            }

            Parallel.ForEach(javaw_strings, keyValuePair =>
            {
                if (result.Contains(keyValuePair.Key)
                && link == "https://pastebin.com/raw/uu6excEE")
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.IN_INSTANCE, keyValuePair.Value, Informations));
                }
            });


            for (int j = 0; j < clientsdetected.Count; j++)
            {
                SMT_Main.RESULTS.bypass_methods.Add(clientsdetected[j]);
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
                            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "Security logs deleted", Informations));
                        }
                    }
                });

                Parallel.ForEach(System_entries, (Security) =>
                {
                    if (PC_StartTime() <= Security.TimeGenerated)
                    {
                        if (Security.InstanceId == 104)
                        {
                            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "\"Security\" logs deleted", Informations));
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
                    if (Application_log.EventID == 3079 && PC_StartTime() <= Application_log.TimeGenerated)
                    {
#pragma warning restore CS0618 // Il tipo o il membro è obsoleto
                        SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "USN Journal was deleted", Application_log.TimeGenerated.ToString()));
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

                    if (entry.TimeCreated <= PC_StartTime())
                    {
                        continue;
                    }

                    IList<EventProperty> properties = entry.Properties;
                    DateTime previousTime = DateTime.Parse(properties[4].Value.ToString());
                    DateTime newTime = DateTime.Parse(properties[5].Value.ToString());

                    if (Math.Abs((previousTime - newTime).TotalMinutes) > 5)
                    {
                        SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "System time change", $"Old -> {previousTime} New -> {newTime}"));
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
                        if (MinecraftMainProcess != "" && dodo.TimeCreated >= Process.GetProcessesByName(MinecraftMainProcess)[0].StartTime)
                        {
                            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "Explorer was restarted after Minecraft", dodo.TimeCreated.ToString()));
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
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "DPS was restarted", Informations));
                    break;
                case "800990970830118099000":
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "PcaSvc", Informations));
                    break;
                case "680105097010308401140970990107000":
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "DiagTrack was restarted", Informations));
                    break;
                case "830121011507709701050110000":
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "Prefetch was disabled (Sysmain restarted)", Informations));
                    break;
            }

            Console.WriteLine(Detection(DETECTION_VALUES.STAGE_PRC, "", "Eventvwr check completed"));
        } //Refractored

        public void OtherChecks()
        {
            Console.OutputEncoding = Encoding.Unicode;
            List<string> journal_names = new List<string>();
            List<string> tda = new List<string>();
            bool unicode_char = false;

            //Check if Recent is empty

            others_tasks.Add(Task.Run(() =>
            {
                string[] s = Directory.GetFiles(Environment.GetFolderPath(Environment.SpecialFolder.Recent));

                if (s.Length == 0)
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "Recent is empty", Informations));
                }

            }));

            //WMIC

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
                        try
                        {
                            if (!check_for_recycle.ContainsKey(correct_key.GetValueNames().Count()) && !check_for_recycle.ContainsValue(subkey_name))
                            {
                                check_for_recycle.Add(correct_key.GetValueNames().Count(), subkey_name);
                            }
                        }
                        catch 
                        {
                            SMT_Main.RESULTS.report_bugs.Add("Recycle.bin error: " + correct_key.GetValueNames().Count() + " " + subkey_name);
                        }

                        foreach (string values in correct_key.GetValueNames())
                        {
                            if (values.Contains(":")
                                && values.Contains(@"\Device\HarddiskVolume4\"))
                            {
                                Match mch = jessica.Match(values);
                                regedit_replace = DiscoC.Replace(mch.Value, $"{Path.GetPathRoot(Environment.SystemDirectory)}");

                                SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, regedit_replace, "Wmic started few days ago #2"));
                            }
                            else if (values.Contains(":")
                                && !values.Contains(@"\Device\HarddiskVolume4\"))
                            {
                                SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, values, "Wmic started few days ago #2"));
                            }
                        }
                    }
                });
            }

            IOrderedEnumerable<KeyValuePair<int, string>> sortedDict = from entry in check_for_recycle orderby entry.Key ascending select entry;

            SMT_Main.RESULTS.recyble_bins = File.GetLastWriteTime($@"C:\$Recycle.bin\{sortedDict.ElementAt(sortedDict.Count() - 1).Value}").ToString();

                #endregion

            }));

            others_tasks.Add(Task.Run(() =>
            {

                #region Disabilitazione del Prefetch #1 e #2

                RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters");

                if (key.GetValue("EnablePrefetcher").ToString() != "3")
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "Prefetch was disabled", Informations));
                }

                try
                {
                    ServiceController sc = new ServiceController("SysMain");

                    if (sc.Status != ServiceControllerStatus.Running)
                    {
                        SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "Prefetch was disabled", Informations));
                    }
                }
                catch
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "Prefetch was disabled", Informations));
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

                string default_mc_path = $@"C:\Users\{username}\AppData\Roaming\.minecraft\versions";
                string[] version_Directories = Directory.GetDirectories(default_mc_path);
                int inUsingFile = 0;

                WebClient wb = new WebClient();
                string s = wb.DownloadString("https://pastebin.com/raw/vrcAF3dq");

                ManagementClass mngmtClass = new ManagementClass("Win32_Process");
                Regex getversion = new Regex("--version.*?--gameDir");

                foreach (ManagementObject o in mngmtClass.GetInstances())
                {
                    if (o["Name"].ToString() == MinecraftMainProcess + ".exe")
                    {
                        Match sda = getversion.Match(o["CommandLine"].ToString());

                        if (sda.Success)
                        {
                            string version = sda.Value.Replace("--version ", "").Replace(" --gameDir", "");

                            if (version[0] == '\"' && version[version.Length - 1] == '\"')
                            {
                                StringBuilder sb = new StringBuilder(version);
                                sb.Remove(0, 1);

                                int reutnr_value = version.Length - 2;

                                sb.Remove(reutnr_value, 1);
                                version = sb.ToString();
                            }

                            string jar_file = default_mc_path + "\\" + version + "\\" + version + ".jar";

                            if (IsFileLocked(new FileInfo(jar_file)))
                            {
                                inUsingFile++;

                                if (!GL_Contains(s, calcoloSHA256(new FileStream(jar_file, FileMode.Open)))
                                && !Process.GetProcessesByName(MinecraftMainProcess)[0].MainWindowTitle.Contains("Lunar")
                                && !Process.GetProcessesByName(MinecraftMainProcess)[0].MainWindowTitle.Contains("Badlion"))
                                {
                                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD,
                                        $"Modified version found: {version}", "(SHA256 check from 1.8 version to 1.16.5)"));
                                }
                            }
                        }
                        else
                        {
                            SMT_Main.RESULTS.report_bugs.Add("MC Version title: " + Process.GetProcessesByName(MinecraftMainProcess)[0].MainWindowTitle 
                                + "\n" + "Command-line error:\n\n" + o["CommandLine"].ToString());

                            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $"Impossible to get {o["Name"]}'s informations", $"PID: {int.Parse(o["Handle"].ToString())}"));
                        }
                    }
                }

                if (inUsingFile > 1)
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "More than 1 version is used", "(BETA Method)"));
                }
                else if (inUsingFile == 0)
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "No versions used in .minecraft", "(BETA Method)"));
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
                    catch (UnauthorizedAccessException)
                    {
                        SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $"{d}", "got readonly permission"));
                    }
                });
            }));

            others_tasks.Add(Task.Run(() =>
            {

                #region PcaClient e MountVol

                string[] get_PCACLIENT = File.ReadAllLines($@"C:\ProgramData\SMT-{SMTDir}\explorer.txt");
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
                        && !GL_Contains(index, $": {username}@file:///")
                        && !index.Contains("?")
                        && !GL_Contains(index, "\""))
                    {
                        int count = index.Replace("file:///", "").Count(f => f == ':');

                        if (count == 1)
                        {
                            if (!GL_Contains(index, "."))
                            {
                                to_distinct.Add("[VISITED FOLDER] " + index.Replace("file:///", "").Replace("%20", " "));
                            }
                            else if (GL_Contains(index, "."))
                            {
                                to_distinct.Add(index.Replace("file:///", "").Replace("%20", " "));
                            }
                        }
                    }

                    if (GL_Contains(index, "pcaclient")
                    && GL_Contains(index, "trace")
                    && index.Length > 27)
                    {
                        Match path = correctPath.Match(index);

                        if (path.Success && path.Value.Length > 0)
                        {
                            string d = path.Value;
                            d = d.Remove(d.Length - 1, 1) + "";

                            SMT_Main.RESULTS.pcaclient.Add(d);
                        }
                    }
                    else if (GL_Contains(index, @"\\?\volume{")
                    && GL_Contains(index, "-")
                    && prefetchfiles.Where(x => x.Contains(Path.GetFileName("MOUNTVOL.EXE").ToUpper())).FirstOrDefault() != null
                    && index.Length >= 50)
                    {
                        Match volume = mountvol_Method.Match(index);

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
                List<string> sas = to_distinct.Distinct().ToList();

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
                    SMT_Main.RESULTS.report_bugs.Add("Explorer file is empty, this error is automatically reported to developer =)");
                }

                #endregion

            }));

            #region Metodo carattere speciale + Regedit aperto + Java/Javaw

            Parallel.ForEach(prefetchfiles, (index) =>
            {
                unicode_char = ContainsUnicodeCharacter(index);

                if (File.GetLastWriteTime(index) >= PC_StartTime())
                {
                    if (File.GetLastWriteTime(index) >= Process.GetProcessesByName(MinecraftMainProcess)[0].StartTime)
                    {
                        if (unicode_char)
                        {
                            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "Special char found", index));
                        }
                        else if (GL_Contains(index, "regedit.exe"))
                        {
                            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "Regedit opened after Minecraft, please investigate", File.GetLastWriteTime(index).ToString()));
                        }
                        else if (GL_Contains(index, "regsvc32.exe"))
                        {
                            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "Regsvc32 used after Minecraft, please investigate", File.GetLastWriteTime(index).ToString()));
                        }
                    }

                    if (GL_Contains(index, "java.exe"))
                    {
                        foreach (string s in Prefetch.PrefetchFile.Open(index).Filenames)
                        {
                            Match volume = javajar_method.Match(s);

                            if (volume.Success && volume.Value.Length > 0)
                            {
                                string trytoget_disk = s.Replace(volume.Value, Path.GetPathRoot(Environment.SystemDirectory));

                                if (!journal_names.Contains(trytoget_disk))
                                {
                                    journal_names.Add(trytoget_disk);
                                }

                                Random r = new Random();

                                if (File.Exists(trytoget_disk))
                                {
                                    try
                                    {
                                        using (ZipFile targetZipFile = ZipFile.Read(trytoget_disk))
                                        {
                                            foreach (ZipEntry zipItem in targetZipFile)
                                            {
                                                if (GL_Contains(zipItem.ToString(), "meta-inf"))
                                                {
                                                    string dir = $@"{Path.GetTempPath()}\SMT-{r.Next(1000, 9999)}-{randomStr()}";
                                                    Directory.CreateDirectory(dir);

                                                    zipItem.Extract(dir);

                                                    using (StreamReader sr = new StreamReader($@"{dir}\META-INF\MANIFEST.MF"))
                                                    {
                                                        string f = File.ReadAllText($@"{dir}\META-INF\MANIFEST.MF");

                                                        if (GL_Contains(f, "main-class"))
                                                        {
                                                            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $"{trytoget_disk.Replace(@"\\", "\\")} is runnable", "Found in JAVA/JAVAW's Prefetch (Possible java -jar?)"));
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

#if !DEBUG

            Regex regex_path = new Regex(@"[A-Z]:\\.*?$");
            string[] CSRSS_file = File.ReadAllLines($@"C:\ProgramData\SMT-{SMTDir}\csrss.txt");

            Parallel.ForEach(CSRSS_file, (index) =>
            {
                Match Csrss_path = regex_path.Match(index);

                if (Csrss_path.Success && File.Exists(Csrss_path.Value))
                {
                    //if (Path.GetExtension(Csrss_path.Value).Length == 0)
                    //{
                    //    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $"No extension found: {Csrss_path.Value}", Informations));
                    //}
                    //else if (Csrss_path.Value.Length >= 5 && Path.GetExtension(Csrss_path.Value).ToUpper() != ".DLL" /* && !suspy_extension.Contains(Path.GetExtension(index.ToUpper()))*/ && FileUtilities.isSpoofedExtension(Csrss_path.Value) && File.ReadAllText(Csrss_path.Value).Contains("AllocConsole") && File.ReadAllText(Csrss_path.Value).Contains("AdjustTokenPrivileges"))
                    //{
                    //    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $"Spoofed extension found: {Csrss_path.Value}", $"This file is a DLL!"));
                    //}

                    if (suspy_extension.Contains(Path.GetExtension(index.ToUpper())))
                    {
                        if (prefetchfiles.Where(x => x.Contains(Path.GetFileName(Csrss_path.Value).ToUpper())).FirstOrDefault() != null
                            && prefetchfiles.Where(f => File.GetLastWriteTime(Csrss_path.Value) >= PC_StartTime()).FirstOrDefault() != null)
                        {
                            if (GetSign(Csrss_path.Value) != "Signed")
                            {
                                try
                                {
                                    if (!GL_Contains(Csrss_path.Value, "strings2"))
                                    {
                                        if (!GL_Contains(Csrss_path.Value, "unprotect"))
                                        {
                                            SMT_Main.RESULTS.suspy_files.Add(Detection(DETECTION_VALUES.UNSIGNED, Csrss_path.Value, "This file hasn't got any digital signature, please investigate"));
                                        }
                                        else if (GL_Contains(Csrss_path.Value, "unprotect") && calcoloSHA256(new FileStream(Csrss_path.Value, FileMode.Open)) != "7c8b131c5222b69ccfd6664fb9c7d93b071e7f377d1fe8b224cf6ea4367a379f")
                                        {
                                            SMT_Main.RESULTS.suspy_files.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, Csrss_path.Value, "This file isn't original \"unprotect\""));
                                        }
                                    }
                                    else if (GL_Contains(Csrss_path.Value, "strings2") && calcoloSHA256(new FileStream(Csrss_path.Value, FileMode.Open)) != "736f66305b85b1ff01b735491db3fae966815ba9ae830c3fec1ab750430f5cdf")
                                    {
                                        SMT_Main.RESULTS.suspy_files.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, Csrss_path.Value, "This file isn't original \"strings2\""));
                                    }
                                }
                                catch
                                {

                                }
                            }
                        }
                    }
                }
                //else if (Csrss_path.Success && !File.Exists(Csrss_path.Value))
                //{
                //    journal_names.Add(Csrss_path.Value);
                //}
                //else if (Csrss_path.Success && Path.GetExtension(Csrss_path.Value).ToUpper() == ".DLL")
                //{
                //    try
                //    {
                //        if (File.Exists(Csrss_path.Value)
                //            && File.ReadAllText(Csrss_path.Value).Contains("AllocConsole")
                //            && File.ReadAllText(Csrss_path.Value).Contains("AdjustTokenPrivileges")
                //            && FileUtilities.isInjectableDll(Csrss_path.Value))
                //        {
                //            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $"Possible DLL Injected: {Csrss_path.Value}", Informations));
                //        }
                //        else if (!File.Exists(Csrss_path.Value))
                //        {
                //            journal_names.Add(Csrss_path.Value);
                //        }
                //    }
                //    catch { }
                //}
            });

#endif

            SMT_Main.RESULTS.suspy_files.Sort();

            Task.WaitAll(others_tasks.ToArray());

            #region Check Journal

            int cacls_counter = 0;

            Win32Api.USN_JOURNAL_DATA data = new Win32Api.USN_JOURNAL_DATA();

            foreach (DriveInfo drive in drives)
            {
                if (drive.IsReady && !GL_Contains(drive.DriveFormat, "fat32"))
                {
                    if (volumeStatus_Check(drive.Name))
                    {
                        SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $"USN Journal isn't active for {drive.Name} volume", Informations));
                    }

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
                                    if (GL_Contains(d.Name, "ConsoleHost_history.txt"))
                                    {
                                        string s = getDirectoryfromJournal(journal, d, drive);

                                        if ((d.Reason == 4096 || d.Reason == 2147484160) && s != "Unavailable" && GL_Contains(s, $@"C:\Users\{username}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"))
                                        {
                                            SMT_Main.RESULTS.possible_replaces.Add(Detection(DETECTION_VALUES.FILE_MOVED_RENAMED, "Powershell history was deleted/removed/renamed", $"File renamed after Minecraft {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                        }
                                    }

                                    if (GL_Contains(d.Name, ".lnk"))
                                    {
                                        string s = getDirectoryfromJournal(journal, d, drive);
                                        string path = Environment.GetFolderPath(Environment.SpecialFolder.Recent);

                                        if (s == "Unavailable" && s.Contains(path) && GL_Contains(d.Name, ".pf"))
                                        {
                                            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, d.Name, $"PF file was edited"));
                                        }
                                    }

                                    if (returnReason(d.Reason).Length > 0)
                                    {
                                        string getPath = getDirectoryfromJournal(journal, d, drive);

                                        foreach (string f in journal_names)
                                        {
                                            if (GL_Contains(f, d.Name) && (d.Reason == 2147484160 || d.Reason == 4096 || d.Reason == 8192))
                                            {
                                                if (TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)
                                                        >= Process.GetProcessesByName(MinecraftMainProcess)[0].StartTime)
                                                {
                                                    SMT_Main.RESULTS.possible_replaces.Add(Detection(DETECTION_VALUES.FILE_DELETED, d.Name + " on: " + drive.Name + " volume (FROM JAVA.EXE Prefetch's log)", $"File deleted after Minecraft {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                                }
                                            }
                                        }

                                        if (d.Reason == 2147483652 && Path.GetExtension(d.Name).ToUpper() == ".PF")
                                        {
                                            SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, d.Name, "PF file was edited"));
                                        }

                                        if (d.Reason == 2149581088 || d.Reason == 2147483744)
                                        {
                                            if (getPath != "Unavailable")
                                            {
                                                SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, getPath, $"Wmic method started today at {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                            }
                                            else if (getPath == "Unavailable")
                                            {
                                                SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, d.Name + " on: " + drive.Name + " volume", $"Wmic method started today at {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                            }
                                        }

                                        else if (suspy_extension.Contains(Path.GetExtension(d.Name.ToUpper())) && TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp) >= Process.GetProcessesByName(MinecraftMainProcess)[0].StartTime)
                                        {
                                            if (!GL_Contains(d.Name, "jnativehook") && !GL_Contains(Path.GetExtension(d.Name), ".dll"))
                                            {
                                                switch (d.Reason)
                                                {
                                                    case 4096:
                                                        if (getPath != "Unavailable")
                                                        {
                                                            SMT_Main.RESULTS.possible_replaces.Add(Detection(DETECTION_VALUES.FILE_MOVED_RENAMED, getPath, $"File renamed after Minecraft {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                                        }
                                                        else if (getPath == "Unavailable")
                                                        {
                                                            SMT_Main.RESULTS.possible_replaces.Add(Detection(DETECTION_VALUES.FILE_MOVED_RENAMED, d.Name + " on: " + drive.Name + " volume", $"File renamed after Minecraft {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                                        }

                                                        break;

                                                    case 2147484160:
                                                        if (File.Exists(getPath))
                                                        {
                                                            if (getPath != "Unavailable")
                                                            {
                                                                SMT_Main.RESULTS.possible_replaces.Add(Detection(DETECTION_VALUES.FILE_REPLACED, getPath, $"File was replaced after Minecraft {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                                            }
                                                            else if (getPath == "Unavailable")
                                                            {
                                                                SMT_Main.RESULTS.possible_replaces.Add(Detection(DETECTION_VALUES.FILE_REPLACED, d.Name + " on: " + drive.Name + " volume", $"File was replaced after Minecraft {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                                            }
                                                        }
                                                        else
                                                        {
                                                            if (getPath != "Unavailable")
                                                            {
                                                                SMT_Main.RESULTS.possible_replaces.Add(Detection(DETECTION_VALUES.FILE_DELETED, getPath, $"File was deleted after Minecraft {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                                            }
                                                            else if (getPath == "Unavailable")
                                                            {
                                                                SMT_Main.RESULTS.possible_replaces.Add(Detection(DETECTION_VALUES.FILE_DELETED, d.Name + " on: " + drive.Name + " volume", $"File was deleted after Minecraft {TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp)}"));
                                                            }
                                                        }
                                                        break;
                                                }
                                            }
                                            else if (GL_Contains(d.Name, "jnativehook") && GL_Contains(Path.GetExtension(d.Name), ".dll"))
                                            {
                                                SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.OUT_INSTANCE, "Generic JNativeHook Clicker (deleted)", TimeZone.CurrentTimeZone.ToLocalTime(d.TimeStamp).ToString()));
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
                        SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $"Impossible to get informations from {drive.Name}", Informations));
                    }
                }
                else
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, $"USN Journal isn't active for {drive.Name} volume", Informations));
                }
            }

            Parallel.For(0, GetTemp_files.Count, (index) =>
            {
                if (GetTemp_files[index].Contains("JNATIVEHOOK")
                    && File.GetLastWriteTime(GetTemp_files[index])
                    >= Process.GetProcessesByName(MinecraftMainProcess)[0].StartTime)
                {
                    SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.OUT_INSTANCE, "Generic JNativeHook Clicker", File.GetLastWriteTime(GetTemp_files[index]).ToString()));
                }
            });

            if (File.GetLastWriteTime($@"C:\Users\{username}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine") >= Process.GetProcessesByName(MinecraftMainProcess)[0].StartTime)
            {
                SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "Powershell history modified or command issued after Minecraft ran", File.GetLastWriteTime($@"C:\Users\{username}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine").ToString()));
            }

            if (cacls_counter >= 3)
            {
                SMT_Main.RESULTS.bypass_methods.Add(Detection(DETECTION_VALUES.BYPASS_METHOD, "Cacls method started today", Informations));
            }

            Console.WriteLine(Detection(DETECTION_VALUES.STAGE_PRC, "", "USNJournal check completed"));

            #endregion

            Console.WriteLine(Detection(DETECTION_VALUES.STAGE_PRC, "", "Other checks completed"));
        } //Refractored

        public void DoStringScan()
        {
            List<Task> tasks = new List<Task>();

            Task DPS = new Task(delegate { StringScannerSystem("https://pastebin.com/raw/adJN0gu4", '§', $@"C:\ProgramData\SMT-{SMTDir}\Specific.txt"); });
            DPS.Start(); tasks.Add(DPS);

            Task LSASS = new Task(delegate { StringScannerSystem("https://pastebin.com/raw/1LKLuNWh", '§', $@"C:\ProgramData\SMT-{SMTDir}\Browser.txt"); });
            LSASS.Start(); tasks.Add(LSASS);

            Task DNS = new Task(delegate { StringScannerSystem("https://pastebin.com/raw/1LKLuNWh", '§', $@"C:\ProgramData\SMT-{SMTDir}\dns.txt"); });
            DNS.Start(); tasks.Add(DNS);

            Task.WaitAll(tasks.ToArray());

            Console.WriteLine(Detection(DETECTION_VALUES.STAGE_PRC, "", "Specific client check completed"));
        }
    }
}