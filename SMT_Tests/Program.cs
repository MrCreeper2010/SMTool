using System;
using System.Collections.Generic;
using System.Diagnostics;
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
        static void Main()
        {
            SignEX sign = new SignEX(8780);
            string dstrna = "luy";
            byte[] to_read = Encoding.Default.GetBytes(dstrna);
            byte[] to_write = Encoding.Default.GetBytes("ddddddddddddd");

            Console.WriteLine(sign.WriteBytes(to_read, to_write));

            Console.WriteLine("done");
            Console.ReadLine();
        }
    }
}
