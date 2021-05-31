using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SMT.helpers;
using SMT.Helpers;
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
    public class Generics : Wrapper
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

            generic_tasks.Add(Task.Run(() =>
            {
                int explorerPID = Process.GetProcessesByName("explorer")[0].Id;

                if (MinecraftMainProcess != "")
                {
                    int javaw = Process.GetProcessesByName(MinecraftMainProcess)[0].Id;

                    SMT_Main.RESULTS.processes_starts.Add("Javaw: ", Process.GetProcessById(javaw).StartTime.ToString());
                }
                else
                {
                    SMT_Main.RESULTS.processes_starts.Add("Javaw: ", "missed");
                }

                SMT_Main.RESULTS.processes_starts.Add("Explorer: ", Process.GetProcessById(explorerPID).StartTime.ToString());
                SMT_Main.RESULTS.processes_starts.Add("System: ", PC_StartTime().ToString());

            }));

            #endregion

            #region Get Input Devices

            generic_tasks.Add(Task.Run(() =>
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_PointingDevice");

                List<ManagementObject> Mouse_device = searcher.Get().Cast<ManagementObject>().ToList();

                Parallel.ForEach(Mouse_device, (index) =>
                {
                    SMT_Main.RESULTS.mouse.Add(index["Name"].ToString());
                });
            }));

            #endregion

            #region Recording Software

            generic_tasks.Add(Task.Run(() =>
            {

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
                        SMT_Main.RESULTS.recording_softwares.Add(index + ", ");
                        recordingProcessesFound++;
                    }
                });
            }));

            #endregion

            #region XRay Resource Pack

            generic_tasks.Add(Task.Run(() =>
            {
                try
                {
                    string[] Get_ResourcePacks = Directory.GetFiles($@"C:\Users\{GlobalVariables.username}\AppData\Roaming\.minecraft\resourcepacks\");
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
            }));

            #endregion

            #region Alts

            generic_tasks.Add(Task.Run(() =>
            {
                int alts_counter = 0;

                try
                {
                    var obj = JsonConvert.DeserializeObject<JObject>(File.ReadAllText($@"C:\Users\{username}\AppData\Roaming\.minecraft\launcher_accounts.json"));
                    Regex rgx = new Regex("\".*?\"");

                    foreach (var s in obj["accounts"])
                    {
                        Match mhc = rgx.Match(s.ToString());

                        if (mhc.Success)
                        {
                            SMT_Main.RESULTS.alts.Add(obj["accounts"][mhc.Value.Replace("\"", "")]["minecraftProfile"]["name"].ToString() + ", ");
                            alts_counter++;
                        }
                    }
                }
                catch
                {
                    SMT_Main.RESULTS.alts.Add("No Alt(s) found(s)");
                }

                if (alts_counter == 0)
                {
                    SMT_Main.RESULTS.alts.Add("No Alt(s) found(s)");
                }

            }));

            #endregion

            Task.WaitAll(generic_tasks.ToArray());

            Console.WriteLine(Detection(DETECTION_VALUES.STAGE_PRC, "", "Generic checks completed"));
        }
    }
}
