using SMT.helpers;
using System;
using System.Diagnostics;
using System.Reflection;

namespace SMT
{
    public class Header
    {
        public Header()
        {
            Console.Title = $"SMT v-{VERSION} (Javaw check disabled)";
        }

        public static string VERSION => FileVersionInfo.GetVersionInfo(Assembly.GetExecutingAssembly().Location).FileVersion;

        public void Check_Updates()
        {
            if (VERSION != SMTHelper.DownloadString("https://pastebin.com/raw/8CFatqcd"))
            {
                ConsoleHelper.WriteLine(SMTHelper.DownloadString("https://pastebin.com/raw/BLLzHGhc"), ConsoleColor.Yellow);
                SMTHelper.Wait();
                Environment.Exit(0);
            }
        }
    }
}
