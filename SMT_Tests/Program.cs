using System;
using System.Collections.Generic;   
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SMT_Tests
{
    class Program
    {
        static void Main(string[] args)
        {
            List<string> prefetchfiles = Directory.GetFiles(@"C:\Windows\Prefetch").ToList();
            string line = "";

            Parallel.ForEach(prefetchfiles, (index) =>
            {
                if (index.ToUpper().Contains("JAVA.EXE"))
                {
                    Parallel.ForEach(Prefetch.PrefetchFile.Open(index).Filenames, (file_name) =>
                    {
                        string file_to_analyze = Regex.Replace(file_name, "\\\\VOLUME.*?\\\\", Path.GetPathRoot(Environment.SystemDirectory));

                        if (File.Exists(file_to_analyze)
                        && file_to_analyze != @"C:\$MFT")
                        {
                            using (StreamReader sr = new StreamReader(file_to_analyze))
                            {
                                while ((line = sr.ReadLine()) != null)
                                {
                                    if (line[0] == 'P' && line[1] == 'K')
                                    {
                                        if (Path.GetExtension(file_to_analyze).Length == 0)
                                        {
                                            Console.WriteLine(file_to_analyze + " no extension");
                                        }
                                        else if (Path.GetExtension(file_to_analyze).Length > 0)
                                        {
                                            Console.WriteLine(file_to_analyze);
                                        }
                                    }

                                    break;
                                }
                            }
                        }
                        //else if(!File.Exists(file_to_analyze))
                        //{
                        //    Console.WriteLine(file_to_analyze + " non esiste");
                        //}
                    });
                }
            });
            
            Console.ReadLine();
        }
    }
}
