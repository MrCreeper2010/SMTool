using SMT.helpers;
using SMT.Helpers;
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;

namespace SMT
{
    public class Initializer : GlobalVariables
    {
        public Initializer()
        {

            #region Titolo e check versione

            string VERSION = FileVersionInfo.GetVersionInfo(Assembly.GetExecutingAssembly().Location).FileVersion;

            //Console.Title = $"SMT v-{VERSION} (Javaw check disabled)";

            /*if (VERSION != Wrapper.DownloadString("https://pastebin.com/raw/8CFatqcd"))
            {
                Wrapper.WriteLine(Wrapper.DownloadString("https://pastebin.com/raw/BLLzHGhc"), ConsoleColor.Yellow);
                Wrapper.Wait();
                Environment.Exit(0);
            }*/

            #endregion

            #region Priorità e limite massimo di Threads

            Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.RealTime;
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

            int workerThreads, complete;
            ThreadPool.GetMinThreads(out workerThreads, out complete);

            ThreadPool.SetMinThreads(200, complete);

            #endregion

            #region Estrazione files e disabilitazione chiusura del programma

            DeleteMenu(GetSystemMenu(GetConsoleWindow(), false), SC_CLOSE, MF_BYCOMMAND);

            Wrapper.ExtractFile();
            Wrapper.SaveAllFiles();

            #endregion

            #region Check errore permessi

            try
            {
                for (int j = 0; j < prefetchfiles.Count; j++)
                {

                }

                for (int j = 0; j < GetTemp_files.Count; j++)
                {

                }
            }
            catch (DirectoryNotFoundException)
            {
                Console.WriteLine("PC can't grant permissions to access to %temp% or Prefetch");
                Wrapper.Wait();
                Environment.Exit(1);
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("PC can't grant permissions to access to %temp% or Prefetch");
                Wrapper.Wait();
                Environment.Exit(1);
            }

            #endregion

        }
    }
}
