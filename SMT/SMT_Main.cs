using Discord;
using SMT.helpers;
using SMT.Helpers;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;

namespace SMT
{
    public static class SMT_Main
    {
        /// <summary>
        /// Welcome to our source little skidder <3 
        /// - by MrCreeper2010 || @CheatReleaseItalyv2 on Telegram
        /// </summary>

        /*
         *  1.Vari checks powershell
            2.Clicker bat Eventi ps
            3.Checks solo lettura cronologia pw
         */

        public static Results RESULTS = new Results();

        public static long final_scan = 0;

        private static void Main()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);

            if (Wrapper.isMCRunning() && principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                Initializer initializer = new Initializer();

                File.CreateText(GlobalVariables.file).Close();

                Stopwatch stopwatch = new Stopwatch();

                Wrapper.WriteLine("Mangiamo sti baby shitty Giulio Piombini...\n", ConsoleColor.Yellow);

                stopwatch.Start();

                Wrapper.doScan();

                stopwatch.Stop();

                final_scan = stopwatch.ElapsedMilliseconds;

                Console.Clear();
                Wrapper.WriteLine($"[?] Press enter to print results (Time elapsed from start scanning: {stopwatch.ElapsedMilliseconds}ms)", ConsoleColor.Yellow);
                Console.ReadLine();

                //Get Results
                Wrapper.enumResults();

                //Clean files
                Wrapper.GoodBye();
            }
            else if (principal.IsInRole(WindowsBuiltInRole.Administrator) == false)
            {
                Console.WriteLine("Administrator's permissions disabled! (Bypass method to bypass tools without drivers)");

                try
                {
                    File.CreateText(GlobalVariables.file).Close();
                    FileStream mystream = new FileStream(Generics.file, FileMode.OpenOrCreate, FileAccess.Write);

                    using (StreamWriter tw = new StreamWriter(mystream))
                    {
                        tw.WriteLine("Administrator's permissions disabled! (Bypass method to bypass tools without drivers)");
                    }

                    DiscordMessage message = new DiscordMessage
                    {
                        Content = $@"L'utente con HWID: {Wrapper.HardwareID()} ha eseguito uno scan di: {final_scan}ms"
                    };

                    Wrapper.Send(message, new FileInfo($@"C:\ProgramData\SMT-{GlobalVariables.SMTDir}\SMT-log.txt"));

                    DiscordMessage message3 = new DiscordMessage
                    {
                        Content = $@"Pare ci sia stato un problema per l'invio del log di SMT..."
                    };

                    Wrapper.Send(message3);

                }
                catch
                {

                }
            }
        }
    }
}