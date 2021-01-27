﻿using System.Collections.Generic;

namespace SMT
{
    public class Results
    {
        #region Check Generics
        public List<string> alts { get; set; } = new List<string>();
        public List<string> mouse { get; set; } = new List<string>();
        public Dictionary<string, string> recyble_bins { get; set; } = new Dictionary<string, string>();
        public List<string> xray_packs { get; set; } = new List<string>();
        public List<string> recording_softwares { get; set; } = new List<string>();
        public bool virtual_machine { get; set; } = false;
        public bool vpn { get; set; } = false;
        public Dictionary<string, string> processes_starts { get; set; } = new Dictionary<string, string>();
        #endregion

        #region Check Scanners
        public List<string> event_viewer_entries { get; set; } = new List<string>();
        public List<string> possible_replaces { get; set; } = new List<string>();
        public List<string> suspy_files { get; set; } = new List<string>();
        public List<string> HeuristicMC { get; set; } = new List<string>();
        public List<string> generic_jnas { get; set; } = new List<string>();
        public List<string> string_scan { get; set; } = new List<string>();
        public List<string> prefetch_files_deleted { get; set; } = new List<string>();
        public List<string> bypass_methods { get; set; } = new List<string>();
        #endregion

        public List<string> Errors { get; set; } = new List<string>();

    }
}
