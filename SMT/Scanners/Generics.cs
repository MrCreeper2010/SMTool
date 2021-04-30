using SMT.helpers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SMT
{
    public class Generics
    {
        #region Generics List Variables

        public List<string> results = new List<string>();
        public string[] alts { get; set; }
        public Dictionary<string, string> recyble_bins { get; set; }
        public string[] xray_packs { get; set; }
        public string[] recording_softwares { get; set; }
        public bool virtual_machine { get; set; }
        public bool vpn { get; set; }
        public Dictionary<string, string> processes_starts { get; set; }

        #endregion

        public void GlobalGeneric_check()
        {
            #region Process Start Time

            int explorerPID = Process.GetProcessesByName("explorer")[0].Id;

            if (Wrapper.MinecraftMainProcess != "")
            {
                int javaw = Process.GetProcessesByName(Wrapper.MinecraftMainProcess)[0].Id;

                SMT_Main.RESULTS.processes_starts.Add("Javaw: ", Process.GetProcessById(javaw).StartTime.ToString());
            }
            else
            {
                SMT_Main.RESULTS.processes_starts.Add("Javaw: ", "missed");
            }

            SMT_Main.RESULTS.processes_starts.Add("Explorer: ", Process.GetProcessById(explorerPID).StartTime.ToString());
            SMT_Main.RESULTS.processes_starts.Add("System: ", Wrapper.PC_StartTime().ToString());

            #endregion

            #region Get Input Devices

            ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_PointingDevice");

            List<ManagementObject> Mouse_device = searcher.Get().Cast<ManagementObject>().ToList();

            Parallel.ForEach(Mouse_device, (index) =>
            {
                SMT_Main.RESULTS.mouse.Add(index["Name"].ToString());
            });

            #endregion

            #region Cestino

            string[] recycleBinFolders = Directory.GetDirectories(@"C:\$Recycle.Bin\");

            Parallel.ForEach(recycleBinFolders, (index) =>
            {
                FileInfo folderInfo = new FileInfo(index);
                DateTime lastEditTime = File.GetLastWriteTime(@"C:\$Recycle.Bin\" + folderInfo.Name);

                SMT_Main.RESULTS.recyble_bins.Add(folderInfo.Name, lastEditTime.ToString());
            });

            #endregion

            #region Recording Software

            int recordingProcessesFound = 0;


            //Check if there is 1 of this process's name in background
            string[] recordingprocesses = new string[]
            {
                "obs64",
                "obs32",
                "Action",
                "RadeonSettings",
                "ShareX",
                "NVIDIA Share",
                "CamRecorder",
                "Fraps",
                "recorder"
            };

            Parallel.ForEach(recordingprocesses, (index) =>
            {
                if (Process.GetProcessesByName(index).Length != 0)
                {
                    SMT_Main.RESULTS.recording_softwares.Add(index);
                    recordingProcessesFound++;
                }
            });

            #endregion

            #region XRay Resource Pack

            try
            {
                string[] Get_ResourcePacks = Directory.GetFiles($@"C:\Users\{Environment.UserName}\AppData\Roaming\.minecraft\resourcepacks\");
                string ResourcePack_line = string.Empty;

                Parallel.ForEach(Get_ResourcePacks, (resourcepack) =>
                {
                    FileInfo finfo = new FileInfo(resourcepack);
                    if (File.ReadAllText(resourcepack).Contains(".json") && finfo.Length < 1000000)
                    {
                        SMT_Main.RESULTS.xray_packs.Add(resourcepack);
                    }
                });
            }
            catch
            {
                SMT_Main.RESULTS.xray_packs.Add("Nothing Found");
            }

            #endregion

            #region Alts

            int total_alts_ctr = 0;
            string launcher_profiles_line = "";

            try
            {
                //Default string -> "displayName" : "MrCreeper2010"
                string launcher_profiles_file = $@"C:\Users\{Environment.UserName}\AppData\Roaming\.minecraft\launcher_accounts.json";

                using (StreamReader read_launcher_profiles = new StreamReader(launcher_profiles_file))
                {
                    while ((launcher_profiles_line = read_launcher_profiles.ReadLine()) != null)
                    {
                        if (launcher_profiles_line.Contains("\"name\" :")) //Ignore all lines without displayName to get profile
                        {
                            Regex displayname_remove = new Regex(@"\"".*?:");
                            string remove_junk1 = displayname_remove.Replace(launcher_profiles_line, "-");  //"displayName" : "MrCreeper2010" -> - "MrCreeper2010"

                            Regex junkstr_remover = new Regex(@"\"".*?\""");
                            Match alt = junkstr_remover.Match(remove_junk1);  //Remove " from name || - "MrCreeper2010" -> MrCreeper2010

                            if (alt.Value.Length > 0
                                && alt.Value.Contains("HuzuniLite"))
                            {
                                SMT_Main.RESULTS.alts.Add("- HuzuniLite (è stato trovato un guapo di Giugliano, attenzione!)");
                            }
                            else if (alt.Value.Length > 0)
                            {
                                SMT_Main.RESULTS.alts.Add(alt.Value);
                                total_alts_ctr++;
                            }
                        }
                        else if (launcher_profiles_line.Contains(",\"name\":"))
                        {
                            Regex displayname_remove = new Regex(",\"name\".*?}");
                            Match mch = displayname_remove.Match(launcher_profiles_line);
                            Regex remove_name = new Regex("\"name\":");
                            Regex remove_graffe = new Regex("}");
                            Regex remove_apostrofi = new Regex("\"");
                            Regex remove_virgole = new Regex(",");

                            string alt_finito = remove_name.Replace(mch.Value, "");
                            alt_finito = remove_graffe.Replace(alt_finito, "");
                            alt_finito = remove_apostrofi.Replace(alt_finito, "");
                            alt_finito = remove_virgole.Replace(alt_finito, "");

                            if (alt_finito.Length > 0 && alt_finito.Contains("HuzuniLite"))
                            {
                                SMT_Main.RESULTS.alts.Add("- HuzuniLite (è stato trovato un guapo di Giugliano, attenzione!)");
                            }
                            else if (alt_finito.Length > 0)
                            {
                                SMT_Main.RESULTS.alts.Add(alt_finito);
                                total_alts_ctr++;
                            }
                        }
                    }
                    read_launcher_profiles.Close();
                }
            }
            catch 
            { 
                SMT_Main.RESULTS.alts.Add("No Alt(s) found(s)"); 
            }

            if (total_alts_ctr == 0)
            {
                SMT_Main.RESULTS.alts.Add("No Alt(s) found(s)");
            }

            #endregion

            Console.WriteLine(Wrapper.Detection(Wrapper.DETECTION_VALUES.STAGE_PRC, "", "Generic checks completed"));
        }

        public void Clean()
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
    }
}
