using Prefetch;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SMT_MethodFinder.Classi
{
    class MF_Methods : Wrapper
    {
        public static List<string> prefetchScan_RESULTS = new List<string>();

        public static void doPrefetchScan(string module)
        {
            Parallel.ForEach(prefetch_Files, (Prefetch_file) =>
            {
                try
                {
                    if (File.GetLastWriteTime(Prefetch_file) >= PC_StartTime())
                    {
                        foreach (var s in PrefetchFile.Open(Prefetch_file).Filenames)
                        {
                            if (GL_Contains(s, module))
                            {
                                prefetchScan_RESULTS.Add(Prefetch_file);
                            }
                        }
                    }
                }
                catch
                {
                    prefetchScan_RESULTS.Add("Impossibile aprire il file: " + Prefetch_file);
                }
            });

            Parallel.ForEach(prefetchScan_RESULTS.Distinct().ToList(), (res) =>
            {
                Console.WriteLine(res);
            });
        }
    }
}
