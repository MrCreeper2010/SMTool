using System.Collections.Generic;

namespace SMT
{
    public class Results
    {
        #region Check Generics

        public List<string> alts { get; set; } = new List<string>();
        public List<string> mouse { get; set; } = new List<string>();
        public long recyble_bins { get; set; }
        public List<string> xray_packs { get; set; } = new List<string>();
        public List<string> recording_softwares { get; set; } = new List<string>();
        public List<string> pcaclient { get; set; } = new List<string>();
        public Dictionary<string, long> processes_starts { get; set; } = new Dictionary<string, long>();
        
        #endregion

        #region Check Scanners
        public List<string> possible_replaces { get; set; } = new List<string>();
        public List<string> suspy_files { get; set; } = new List<string>();
        public List<string> bypass_methods { get; set; } = new List<string>();
        #endregion

        public List<string> report_bugs { get; set; } = new List<string>();
    }
}
