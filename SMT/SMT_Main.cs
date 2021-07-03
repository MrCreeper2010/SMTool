using Discord;
using SMT.helpers;
using SMT.Helpers;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Windows.Forms;

namespace SMT
{
    public static class SMT_Main
    {
        /// <summary>
        /// Welcome to our source little skidder <3 
        /// - by MrCreeper2010 || @CheatReleaseItalyv2 on Telegram
        /// </summary>

        /*
         *  1. fix USB connected
         */

        

        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new Auth());
        }
    }
}