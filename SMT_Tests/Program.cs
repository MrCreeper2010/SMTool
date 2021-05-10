using System;
using System.IO;
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
            StreamWriter sl = File.CreateText($@"C:\users\Mattia\Desktop\ciao.txt");
            sl.Close();

            using(StreamWriter sw = new StreamWriter($@"C:\users\Mattia\Desktop\ciao.txt"))
            {
                sw.WriteLine("tpsto");
                sw.Close();
            }

            Console.WriteLine("done");
            Console.ReadLine();
        }
    }
}
