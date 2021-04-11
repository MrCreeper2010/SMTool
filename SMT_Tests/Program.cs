using System;
using System.Collections.Generic;   
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SMT_Tests
{
    class Program
    {
        static void Main(string[] args)
        {
            List<string> vs = Directory.GetFiles(@"C:\WINDOWS\PREFETCH").ToList();

            var element = vs.Where(x => x.ToUpper().Contains("INSTALLER.EXE")).FirstOrDefault();
            Console.WriteLine(element != null);
            Console.ReadLine();
        }
    }
}
