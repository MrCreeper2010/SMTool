using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text.RegularExpressions;

namespace SMT_Tests
{
    class Program
    {
        public async static void getCommandLine()
        {
            Console.WriteLine("francus");
        }

        static void Main()
        {
            Process.Start(@"C:\users\Mattia\Desktop\video.mp4");

            Console.WriteLine("done");
            Console.ReadLine();
        }
    }
}
