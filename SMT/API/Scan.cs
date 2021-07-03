using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace eSStool.json
{
    public class Scan
    {
        [JsonProperty("id")]
        public string id { get; set; }

        [JsonProperty("userId")]
        public int userId { get; set; }

        [JsonProperty("legit")]
        public bool legit { get; set; }

        [JsonProperty("date")]
        public long date { get; set; }

        [JsonProperty("recycleBinMillis")]
        public long recycleBinMillis { get; set; }

        [JsonProperty("pcType")]
        public string pcType { get; set; }

        [JsonProperty("explorerReport")]
        public string explorerReport { get; set; }

        [JsonProperty("success")]
        public bool success { get; set; }

        [JsonProperty("blocked")]
        public bool blocked { get; set; }

        [JsonProperty("antiss")]
        public bool antiss { get; set; }

        [JsonProperty("endTime")]
        public long endTime { get; set; }

        [JsonProperty("hwid")]
        public string hwid { get; set; }

        [JsonProperty("vpn")]
        public bool vpn { get; set; }

        [JsonProperty("vm")]
        public bool vm { get; set; }

        [JsonProperty("accounts")]
        public List<string> accounts { get; set; }

        [JsonProperty("recordingSoftwares")]
        public List<string> recordingSoftwares { get; set; }

        [JsonProperty("processStartTime")]
        public Dictionary<string, long> processStartTime { get; set; }

        [JsonProperty("connectedDevices")]
        public List<string> connectedDevices { get; set; }

        [JsonProperty("checks")]
        public Dictionary<string, string> checks { get; set; }

        [JsonProperty("pcaClientFiles")]
        public List<string> pcaClientFiles { get; set; }

        [JsonProperty("fileActions")]
        public Dictionary<string, string> fileActions { get; set; }

        [JsonProperty("suspiciousFiles")]
        public List<string> suspiciousFiles { get; set; }

        [JsonProperty("xRayResourcePacks")]
        public List<string> xRayResourcePacks { get; set; }

    }
}
