using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SMT_MethodFinder.Classi
{
    class Header
    {
        public Header()
        {
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

            int workerThreads, complete;
            ThreadPool.GetMinThreads(out workerThreads, out complete);

            ThreadPool.SetMinThreads(200, complete);




        }
    }
}
