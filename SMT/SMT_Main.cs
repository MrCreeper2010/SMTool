using SMT.helpers;
using System;
using System.Diagnostics;

namespace SMT
{
    public static class SMT_Main
    {
        /// <summary>
        /// Welcome to our source little skidder <3 
        /// - by MrCreeper2010 || @CheatReleaseItalyv2 on Telegram
        /// </summary>

        public static Results RESULTS = new Results();

        private static void Main()
        {
            Initializer initializer = new Initializer();

            Stopwatch stopwatch = new Stopwatch();

            if (Wrapper.isMCRunning())
            {
                Wrapper.WriteLine("Mangiamo sti baby shitty Giulio Piombini ...\n", ConsoleColor.Yellow);

                stopwatch.Start();

                Wrapper.doScan();

                stopwatch.Stop();

                bool isDebug = false;

#if DEBUG
                isDebug = true;
#endif

                if (!isDebug)
                    Wrapper.sendMessage($"L'utente con HWID: {Wrapper.HardwareID()} ha totalizzato {stopwatch.ElapsedMilliseconds}ms!" +
                        $"\nUnlegit?: {Wrapper.isLegit()}");
                else
                    Wrapper.sendMessage($"[DEBUG] L'utente con HWID: {Wrapper.HardwareID()} ha totalizzato {stopwatch.ElapsedMilliseconds}ms!" +
                        $"\nUnlegit?: {Wrapper.isLegit()}");

                Console.Clear();
                Wrapper.WriteLine($"[?] Press enter to print results (Time elapsed from start scanning: {stopwatch.ElapsedMilliseconds}ms)", ConsoleColor.Yellow);
                Console.ReadLine();

                //Get Results
                Wrapper.enumResults();

                //Clean files
                Wrapper.GoodBye();
            }
        }
    }
}