using SMT.helpers;
using SMT.Helpers;
using SMT.scanners;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SMT
{
    public static class SMT
    {
        public static Results RESULTS = new Results();
        public static readonly List<Task> tasks = new List<Task>();

        /// <summary>
        /// Welcome to our source little skidder <3 
        /// - by MrCreeper2010
        /// </summary>

        /*
         * DA AGGIUNGERE/RIVEDERE:
         * - Metodo java -jar (se un file SENZA JNativehook viene aperto con java -jar)
         * - False-flags con gli antivirus + Incompatibilità con "Kaspersky"
         */


        private static void ThrowException()
        {
            RESULTS.Errors.Add("An error occured meanwhile SMT was scanning, please restart SMT");
        }

        public static void runCheckAsync(Action check)
        {
            try
            {
#pragma warning disable CS1998 // Il metodo asincrono non contiene operatori 'await', pertanto verrà eseguito in modo sincrono
                tasks.Add(Task.Factory.StartNew(async () => check()));
#pragma warning restore CS1998 // Il metodo asincrono non contiene operatori 'await', pertanto verrà eseguito in modo sincrono
            }
            catch { ThrowException(); }
        }

        private static void Main()
        {
            try
            {
                for (int j = 0; j < SMTHelper.prefetchfiles.Count; j++)
                {

                }

                for (int j = 0; j < SMTHelper.GetTemp_files.Count; j++)
                {

                }
            }
            catch
            {
                ConsoleHelper.WriteLine(@"[-] Prefetch or %temp% unreacheable, possible cacls method?", ConsoleColor.Yellow);
                SMTHelper.Wait();
                Environment.Exit(0);
            }

            Header header = new Header();
            Generics generics = new Generics();
            Checks checks = new Checks();

            header.Check_Updates();

            Stopwatch stopwatch = new Stopwatch();

            if (!SMTHelper.isCorrectMC())
            {
                #region Check 1 - Delete close button - ExtractFile - SaveFiles - Classes - Priority

                Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.High;
                new Thread(() =>
                {
                    while (true)
                    {
                        foreach (ProcessThread processThread in Process.GetCurrentProcess().Threads)
                        {
                            if (processThread.ThreadState != System.Diagnostics.ThreadState.Terminated)
                            {
                                try
                                {
                                    processThread.PriorityLevel = ThreadPriorityLevel.Highest;
                                }
                                catch
                                {

                                }
                            }
                        }

                        Thread.Sleep(50);
                    }
                }).Start();

                SMTHelper.DeleteMenu(SMTHelper.GetSystemMenu(SMTHelper.GetConsoleWindow(), false), SMTHelper.SC_CLOSE, SMTHelper.MF_BYCOMMAND);

                SMTHelper.ExtractFile();
                SMTHelper.SaveAllFiles();

                ConsoleHelper.WriteLine("[+] Pensando a cosa mangiare stasera...\n", ConsoleColor.Yellow);

                stopwatch.Start();

                Action[] AllChecks = new Action[]
                {
                    /*
                     * JAVAW DA RIAGGIUNGERE
                     */

                    checks.DoStringScan,
                    checks.HeuristicCsrssCheck,
                    checks.USNJournal,
                    checks.OtherChecks,
                    checks.EventVwrCheck,
                    generics.GlobalGeneric_check,
                };

                for (int j = 0; j < AllChecks.Length; j++)
                {
                    runCheckAsync(AllChecks[j]);
                }

                Task.WaitAll(tasks.ToArray());

                stopwatch.Stop();

                /*

                    Sono felice che tu abbia aperto il codice sorgente per consultare qualche
                    riga del mio tool, ma il Webhook di Discord altro non fa che memorizzare
                    all'interno di un bot Discord per l'appunto, solamente quanto il tuo check
                    è durato.

                 */

                DiscordWebhook.sendMessage($"L'utente con HWID: {SMTHelper.HardwareID()} ha totalizzato {stopwatch.ElapsedMilliseconds}ms!");

                Console.Clear();
                ConsoleHelper.WriteLine($"[?] Press enter to print results (Time elapsed from start scanning: {stopwatch.ElapsedMilliseconds}ms)", ConsoleColor.Yellow);
                Console.ReadLine();

                #endregion

                #region Write Results (Check 1)
                ConsoleHelper.WriteLine("Generic Informations: \n", ConsoleColor.Green);

                ConsoleHelper.WriteLine("Alts:\n", ConsoleColor.Yellow); //fatto
                RESULTS.alts.Distinct().ToList().ForEach(alt => ConsoleHelper.WriteLine("- " + alt));
                
                ConsoleHelper.WriteLine("\nRecycle.bin:\n", ConsoleColor.Yellow); //fatto
                foreach (KeyValuePair<string, string> recycleBin in RESULTS.recyble_bins)
                {
                    ConsoleHelper.WriteLine($"- {recycleBin.Key} ({recycleBin.Value})");
                }

                if (RESULTS.recording_softwares.Count > 0)
                {
                    ConsoleHelper.WriteLine("\nRecording Software(s):\n ", ConsoleColor.Yellow);

                    RESULTS.recording_softwares.ForEach(recording => ConsoleHelper.WriteLine("- " + recording));
                }
                else
                {
                    Console.WriteLine("- No Recording Software(s) found");
                }

                ConsoleHelper.WriteLine("\nProcess(es) Start Time:\n", ConsoleColor.Yellow); //fatto
                foreach (KeyValuePair<string, string> processStart in RESULTS.processes_starts)
                {
                    ConsoleHelper.WriteLine("- " + processStart.Key + processStart.Value);
                }

                ConsoleHelper.WriteLine("\nXray Resource Pack(s):\n", ConsoleColor.Yellow); //fatto
                if (RESULTS.xray_packs.Count > 0)
                {
                    RESULTS.xray_packs.ForEach(xray => ConsoleHelper.WriteLine("- " + xray));
                }
                else
                {
                    Console.WriteLine("- No Xray resource pack found");
                }

                ConsoleHelper.WriteLine("\nInput Device(s):\n", ConsoleColor.Yellow); //fatto
                if (RESULTS.mouse.Count > 0)
                {
                    RESULTS.mouse.ForEach(mouse => ConsoleHelper.WriteLine("- " + mouse));
                }
                else
                {
                    Console.WriteLine("- No input devices found");
                }

                #endregion

                #region Write Results (Check 2)

                ConsoleHelper.WriteLine("\nChecks:", ConsoleColor.Red);

                if (RESULTS.Errors.Count > 0) // done
                {
                    RESULTS.Errors.Distinct().ToList().ForEach(jna => ConsoleHelper.WriteLine("- " + jna));
                }

                if (RESULTS.possible_replaces.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\nFile's actions file(s):\n", ConsoleColor.Cyan);
                    RESULTS.possible_replaces.Sort();
                    RESULTS.possible_replaces.Distinct().ToList().ForEach(replace => ConsoleHelper.WriteLine("- " + replace));
                }

                if (RESULTS.event_viewer_entries.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\nBad Eventvwr log(s):\n", ConsoleColor.Cyan);
                    RESULTS.event_viewer_entries.Distinct().ToList().ForEach(eventvwr => ConsoleHelper.WriteLine("- " + eventvwr));
                }

                if (RESULTS.suspy_files.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\nGeneric file attributes Check:\n", ConsoleColor.Cyan);
                    RESULTS.suspy_files.Sort();
                    RESULTS.suspy_files.Distinct().ToList().ForEach(suspy => ConsoleHelper.WriteLine("- " + suspy));
                }
                else
                {
                    ConsoleHelper.WriteLine("\nWarning:\n", ConsoleColor.Yellow);
                    Console.WriteLine("- No suspicious file found, if user uses \"Kaspersky\" please disable it and rescan");
                }

                if (RESULTS.bypass_methods.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\nBypass methods:\n", ConsoleColor.Cyan);
                    RESULTS.bypass_methods.Distinct().ToList().ForEach(replace => ConsoleHelper.WriteLine("- " + replace));
                }

                if (RESULTS.string_scan.Count > 0) // done
                {
                    ConsoleHelper.WriteLine("\nString Scan:\n", ConsoleColor.Cyan);
                    RESULTS.string_scan.Distinct().ToList().ForEach(strscn => ConsoleHelper.WriteLine("- " + strscn));
                }

                #endregion

                #region Nothing Found
                if (RESULTS.possible_replaces.Count == 0 && RESULTS.suspy_files.Count == 0
                     && RESULTS.event_viewer_entries.Count == 0
                     && RESULTS.string_scan.Count == 0 && RESULTS.bypass_methods.Count == 0)
                {
                    ConsoleHelper.WriteLine("\nNothing Found", ConsoleColor.Green);
                }
                #endregion

                #region Exit + Clean SMT files
                ConsoleHelper.WriteLine("\nHave a nice day! developed by MrCreeper2010", ConsoleColor.Yellow);
                Console.Write("\nPress any key to exit");
                Console.ReadLine();
                Console.Write("\nConfirm exit -> press any key");
                Console.ReadLine();
                generics.Clean();
                #endregion
            }
            else
            {
                ConsoleHelper.WriteLine("[!] Minecraft missed, press any key to exit", ConsoleColor.Yellow);
                Console.ReadLine();
                Environment.Exit(0);
            }
        }
    }
}