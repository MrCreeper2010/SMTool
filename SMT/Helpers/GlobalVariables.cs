using System.Collections.Generic;

namespace SMT.Helpers
{
    internal class GlobalVariables
    {
        public static readonly List<string> suspy_extension = new List<string>()
        {
            ".EXE",
            ".BAT",
            ".CMD",
            ".COM",
            ".PIF",
            ".PF",
            ".DLL",
        };

        public static readonly List<string> suspy_imports = new List<string>()
        {
            "ReadProcessMemory",
            "WriteProcessMemory",
            "GetKeyState",
            "GetAsyncKeyState",
            "mouse_event",
            "VirtualQueryEx",
            "SendMessage",
        };
    }
}
