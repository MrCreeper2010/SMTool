using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SMT_MethodFinder.Classi
{
    public class Wrapper
    {
        public static string[] prefetch_Files = Directory.GetFiles(@"C:\Windows\Prefetch", "*.pf");

        public static bool GL_Contains(string source, string toCheck)
        {
            return source.IndexOf(toCheck, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static DateTime PC_StartTime()
        {
            return DateTime.Now.AddMilliseconds(-Environment.TickCount);
        }

        public static string WriteLine(string text, ConsoleColor color)
        {
            string return_value = "";

            Console.ForegroundColor = color;
            Console.WriteLine(text);
            Console.ForegroundColor = ConsoleColor.White;

            return return_value;
        }

        public static string Write(string text, ConsoleColor color)
        {
            string return_value = "";

            Console.ForegroundColor = color;
            Console.Write(text);
            Console.ForegroundColor = ConsoleColor.White;

            return return_value;
        }
    }
}
