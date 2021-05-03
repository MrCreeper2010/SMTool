using Ionic.Zip;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;

namespace SMT_Tests
{
    class Program
    {
        public static string getCommand(string file)
        {
            Process p = new Process();

            // Redirect the output stream of the child process.
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.Arguments = $"/C java -jar {file}";

            ProcessStartInfo psi = new ProcessStartInfo();

            psi.CreateNoWindow = true;
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();

            return output;
        }

        public static string randomStr()
        {
            Random r = new Random();

            string return_value = "";
            string all_strings = "abcdefhilmnopqrstuvzABCDEFGHILMNOPQRSTUVZ";

            for(int j = 0; j < 5; j++)
            {
                return_value += all_strings[r.Next(1, 42)];
            }

            return return_value;
        }

        static void Main()
        {
            bool isDebug = false;

#if DEBUG
            isDebug = true;
#endif
            Console.WriteLine(isDebug);


            Console.WriteLine("done");
            Console.ReadLine();
        }
    }
}
