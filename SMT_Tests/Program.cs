using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using ThreeOneThree.Proxima.Agent;
using ThreeOneThree.Proxima.Core;

namespace SMT_Tests
{
    class Program
    {
        static void Main()
        {
            string source = "DASTRINGAG";
            string toCheck = "dastr";

            //if (source == null) return false;
            Console.WriteLine(source.IndexOf(toCheck, StringComparison.OrdinalIgnoreCase) >= 0);


            Console.WriteLine("done");
            Console.ReadLine();
        }
    }
}
