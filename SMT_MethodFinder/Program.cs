using SMT_MethodFinder.Classi;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Prefetch;

namespace SMT_MethodFinder
{
    public class Program : Wrapper
    {
        public static void Main()
        {
            string MF_method = "";
            Classi.Header header = new Classi.Header();
            
            WriteLine("Find string in Prefetch [0]\nCheck patate [1]", ConsoleColor.Yellow);
            MF_method = Console.ReadLine();

            switch(MF_method)
            {
                case "0":
                    WriteLine("Scegli la stringa da cercare", ConsoleColor.Yellow);
                    MF_method = "";
                    MF_method = Console.ReadLine();

                    MF_Methods.doPrefetchScan(MF_method);
                    break;
                case "1":

                    break;
                case "2":

                    break;
            }

            Console.WriteLine("Check finito");
            Console.ReadLine();
        }
    }
}
