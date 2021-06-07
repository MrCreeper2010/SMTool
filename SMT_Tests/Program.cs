using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using Usb.Events;

namespace SMT_Tests
{
    internal class Program
    {
        static readonly IUsbEventWatcher usbEventWatcher = new UsbEventWatcher();

        public static void Main()
        {
            Console.WriteLine(Path.GetPathRoot(Environment.SystemDirectory));

            Console.WriteLine("Finito");
            Console.ReadLine();
        }
    }
}
