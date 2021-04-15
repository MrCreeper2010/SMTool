using System.Collections.Specialized;
using System.Net;

namespace SMT.Helpers
{
    internal class DiscordWebhook
    {
        public const string URL = "https://discord.com/api/webhooks/805963625005187133/M1iOsritwf1i0hq8rkWinDCqLXFWlkI0p4RfOGvBJ2x9D85nr2fMnfbw0_1M_uhMma7U";

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
