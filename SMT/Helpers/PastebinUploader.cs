using PastebinAPI;
using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SMT.Helpers
{
    internal class PastebinUploader
    {
        public static string pastebin_link = "";

        public static async Task PastebinExample(string code)
        {
            Pastebin.DevKey = "fXoblGL8GvuXLbFsYXWzn9tZIMhX96QY";
            Random rnd = new Random();
            
            try
            {
                User me = await Pastebin.LoginAsync("FreschezzaDelleNevi", "peppeilgrosso");
                Paste newPaste = await me.CreatePasteAsync(code, $"SMT Results #{rnd.Next(1000, 9999)}",
                    Language.HTML5, Visibility.Private, Expiration.Never);
                pastebin_link = newPaste.Url;
            }
            catch
            {
                
            }
        }
    }
}
