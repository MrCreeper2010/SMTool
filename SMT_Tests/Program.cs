using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;

namespace SMT_Tests
{
    internal class Program
    {
        public static void Main()
        {
            List<string> ddood = new List<string>();
            List<string> ddood1 = new List<string>();
            List<string> ddood2 = new List<string>();

            ddood.Add("11");

            bool uno = ddood.Count > 0;
            bool due = ddood1.Count > 0;

            //ddood.Add("mUmumj");

            Console.WriteLine(ddood.Count | ddood1.Count | ddood2.Count);

            if((ddood.Count | ddood1.Count & ddood2.Count) != 0)
            {
                Console.WriteLine("BERNICE");
            }

            if (uno | due)
            {
                Console.WriteLine("Interessante");
            }

            Console.WriteLine("Finito");
            Console.ReadLine();
        }
    }
}
