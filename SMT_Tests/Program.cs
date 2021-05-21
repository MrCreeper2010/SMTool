using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace SMT_Tests
{
    class Program
    {
        public static void Main()
        {
            #region Check recording

            //List<string> prefetchfiles = Directory.GetFiles(@"C:\Windows\Prefetch", "*.pf").ToList();
            //List<string> givova = new List<string>();

            //Parallel.ForEach(Process.GetProcesses(), (single_process) =>
            //{
            //    try
            //    {
            //        var processFileName = Path.GetFileName(single_process.MainModule.FileName).ToUpper();

            //        if (GetSign(single_process.MainModule.FileName) != "Signed"
            //        && single_process.MainModule.FileName != Assembly.GetExecutingAssembly().Location
            //        && prefetchfiles.Where(x => x.Contains(processFileName)) != null
            //        && prefetchfiles.Where(f => File.GetLastWriteTime(processFileName)
            //        >= Process.GetProcessesByName("javaw")[0].StartTime) != null)
            //        {
            //            givova.Add(single_process.MainModule.FileName);
            //        }

            //    }
            //    catch
            //    {

            //    }
            //});

            //var m = givova.Distinct().ToList();
            //m.Sort();

            //foreach(var s in m)
            //{
            //    Console.WriteLine(s);
            //}

            #endregion
            string francus = @"\\\\111\\\\33333\888888\VOLUME";

            Regex rgx = new Regex("\\\\.*?\\\\");
            Match mch = rgx.Match(francus);

            if(mch.Success)
            {
                Console.WriteLine(mch.Value);
            }

            Console.WriteLine("Finito");
            Console.ReadLine();
        }
    }
}
