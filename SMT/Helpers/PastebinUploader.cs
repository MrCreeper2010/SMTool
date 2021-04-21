using PastebinAPI;
using SMT.helpers;
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
            Pastebin.DevKey = "API ro zì giggin";
            
            try
            {
                User me = await Pastebin.LoginAsync("PeppeOMalament", "TonioOTrack");
                Paste newPaste = await me.CreatePasteAsync(code, $"SMT Results #{SMTHelper.SMTDir}",
                    Language.HTML5, Visibility.Private, Expiration.Never);
                pastebin_link = newPaste.Url;
            }
            catch
            {
                
            }
        }
    }
}
