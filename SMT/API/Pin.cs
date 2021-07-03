using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace eSStool.json
{
    public class Pin
    {

        [JsonProperty("pin")]
        public int pin { get; set; }

        [JsonProperty("userId")]
        public int userId { get; set; }

        [JsonProperty("used")]
        public bool used { get; set; }

        [JsonProperty("timestamp")]
        public long timestamp { get; set; }

    }
}
