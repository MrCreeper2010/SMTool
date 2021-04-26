using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace SMT_Tests
{
    class Program
    {
        public static bool IsFileLocked(FileInfo file)
        {
            try
            {
                using (FileStream stream = file.Open(FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    stream.Close();
                }
            }
            catch (IOException)
            {
                return true;
            }

            return false;
        }

        public static string calcoloSHA256(FileStream file)
        {
            var sha = new SHA256Managed();

            byte[] bytes = sha.ComputeHash(file);
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }

        static void Main()
        {
            var version_Directories = Directory.GetDirectories($@"C:\Users\{Environment.UserName}\AppData\Roaming\.minecraft\versions");
            int inUsingFile = 0;

            WebClient wb = new WebClient();
            var s = wb.DownloadString("https://pastebin.com/raw/0kjRrqiC");

            Parallel.ForEach(version_Directories, (index) =>
            {
                var version_File = Directory.GetFiles(index, "*.jar");

                for (int j = 0; j < version_File.Length; j++)
                {
                    if (IsFileLocked(new FileInfo(version_File[j])))
                    {
                        inUsingFile++;

                        if (!s.Contains(calcoloSHA256(new FileStream(version_File[j], FileMode.Open))))
                        {
                            Console.WriteLine("NON legittimo");
                        }
                    }
                }
            });

            if (inUsingFile > 1)
            {
                Console.WriteLine("Bypass grosso bro");
            }

            Console.WriteLine("done");
            Console.ReadLine();
        }
    }
}
