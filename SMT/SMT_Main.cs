using SMT.helpers;
using SMT.Helpers;
using SMT.scanners;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SMT
{
    public static class SMT_Main
    {
        /// <summary>
        /// Welcome to our source little skidder <3 
        /// - by MrCreeper2010 || @CheatReleaseItalyv2 on Telegram
        /// </summary>

        public static Results RESULTS = new Results();
        public static readonly List<Task> tasks = new List<Task>();
        public static List<string> CsrssFiles_tocheck = new List<string>();

        private static void Main()
        {
            Initializer initializer = new Initializer();
            Generics generics = new Generics();
            Checks checks = new Checks();

            Stopwatch stopwatch = new Stopwatch();

            if (Wrapper.isMCRunning())
            {
                #region Check 1 - Avvio dello scan e invio del tempo trascorso

                Wrapper.WriteLine("[+] Pensando a cosa mangiare stasera...\n", ConsoleColor.Yellow);

                stopwatch.Start();

                Action[] AllChecks = new Action[]
                {
                    /*
                     * JAVAW DA RIAGGIUNGERE
                     */

                    //checks.DoStringScan,
                    //checks.HeuristicCsrssCheck,
                    //checks.USNJournal,
                    //checks.OtherChecks,
                    //checks.EventVwrCheck,
                    //generics.GlobalGeneric_check,
                };

                for (int j = 0; j < AllChecks.Length; j++)
                {
                    Wrapper.runCheckAsync(AllChecks[j]);
                }

                Task.WaitAll(tasks.ToArray());

                stopwatch.Stop();

                DiscordWebhook.sendMessage($"L'utente con HWID: {Wrapper.HardwareID()} ha totalizzato {stopwatch.ElapsedMilliseconds}ms!");

                Console.Clear();
                Wrapper.WriteLine($"[?] Press enter to print results (Time elapsed from start scanning: {stopwatch.ElapsedMilliseconds}ms)", ConsoleColor.Yellow);
                Console.ReadLine();

                #endregion

                Wrapper.enumResults();

                Wrapper.GoodBye();
            }
        }
    }
}