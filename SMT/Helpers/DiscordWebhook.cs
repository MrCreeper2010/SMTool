using SMT.helpers;
using System.Collections.Specialized;
using System.Net;

namespace SMT.Helpers
{
    internal class DiscordWebhook
    {
        public static string URL = SMTHelper.DownloadString("https://pastebin.com/raw/bQtuHGtA");

        public static byte[] initializeURL(string URL, NameValueCollection pairs)
        {
            using (WebClient web = new WebClient())
            {
                return web.UploadValues(URL, pairs);
            }
        }

        public static void sendMessage(string message)
        {
            initializeURL(URL, new NameValueCollection()
            {
                {
                    "content",
                     message
                }
            });
        }
    }
}
