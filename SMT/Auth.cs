using Discord;
using eSStool.json;
using Newtonsoft.Json;
using SMT.helpers;
using SMT.Helpers;
using SMT.scanners;
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;

namespace SMT
{
    public partial class Auth : Form
    {

        /**
         * Thanks https://stackoverflow.com/questions/18822067/rounded-corners-in-c-sharp-windows-forms
         **/

        [DllImport("Gdi32.dll", EntryPoint = "CreateRoundRectRgn")]
        private static extern IntPtr CreateRoundRectRgn
        (
            int nLeftRect,     // x-coordinate of upper-left corner
            int nTopRect,      // y-coordinate of upper-left corner
            int nRightRect,    // x-coordinate of lower-right corner
            int nBottomRect,   // y-coordinate of lower-right corner
            int nWidthEllipse, // width of ellipse
            int nHeightEllipse // height of ellipse
        );

        public static Results RESULTS = new Results();

        public static long final_scan = 0;

        public Auth()
        {
            InitializeComponent();
            CheckForIllegalCrossThreadCalls = false;
            Region = System.Drawing.Region.FromHrgn(CreateRoundRectRgn(0, 0, Width, Height, 20, 20));
        }

        private void Auth_Load(object sender, EventArgs e)
        {

        }

        private void btnClose_Click(object sender, EventArgs e)
        {
            Environment.Exit(0);
        }

        private void btnMinimize_Click(object sender, EventArgs e)
        {
            WindowState = FormWindowState.Minimized;
        }

        private void btnStart_Click(object sender, EventArgs e)
        {
            if (auth()) {
                lblEnter.Visible = false;
                circularProgressBar1.Visible = true;
                txtPin.Visible = false;
                btnStart.Visible = false;
                bwScanner.RunWorkerAsync();
            }
        }

        public bool auth()
        {
            try
            {
                if (!Wrapper.isMCRunning())
                {
                    return false;
                }
                int pinCode = Convert.ToInt32(txtPin.Text);
                Pin pin = getPinInfo(pinCode);

                if ((Checks.GetCurrentMilli(DateTime.Now) - pin.timestamp) <= 60000)
                {
                    return false;
                }

                if (pin == null || pin.used)
                {
                    return false ;
                }

                //MessageBox.Show("Logged");
                Wrapper.usedPin = pin;
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                MessageBox.Show("Wrong pin.");
                return false;
            }
        }

        public static Pin getPinInfo(int pinInfo)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("http://localhost/pin/" + pinInfo + "/check/");
            request.Method = "GET";
            request.ContentType = "application/json; charset=utf-8";
            request.Headers.Add("SMT-Header:true");
            WebResponse response = request.GetResponse();

            Stream dataStream = response.GetResponseStream();

            StreamReader reader = new StreamReader(dataStream);
            string responseFromServer = reader.ReadToEnd();
            Console.WriteLine(responseFromServer);
            return JsonConvert.DeserializeObject<Pin>(responseFromServer);
        }

        public static Pin usePin(int pinInfo)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("http://localhost/pin/" + pinInfo + "/use/");
            request.Method = "GET";
            request.ContentType = "application/json; charset=utf-8";
            request.Headers.Add("SMT-Header:true");
            WebResponse response = request.GetResponse();

            Stream dataStream = response.GetResponseStream();

            StreamReader reader = new StreamReader(dataStream);
            string responseFromServer = reader.ReadToEnd();
            Console.WriteLine(responseFromServer);
            return JsonConvert.DeserializeObject<Pin>(responseFromServer);
        }

        public static Stopwatch stopwatch = new Stopwatch();

        private void bwScanner_DoWork(object sender, System.ComponentModel.DoWorkEventArgs e)
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            
            if (Wrapper.isMCRunning() && principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                new Initializer();
                File.CreateText(GlobalVariables.file).Close();
                stopwatch.Start();
                
                Wrapper.doScan(bwScanner);
                stopwatch.Stop();
                final_scan = stopwatch.ElapsedMilliseconds;
                Wrapper.enumResults();
            }
            else if (principal.IsInRole(WindowsBuiltInRole.Administrator) == false)
            {
                Console.WriteLine("Administrator's permissions disabled! (Bypass method to bypass tools without drivers)");

                try
                {
                    File.CreateText(GlobalVariables.file).Close();
                    FileStream mystream = new FileStream(Generics.file, FileMode.OpenOrCreate, FileAccess.Write);

                    using (StreamWriter tw = new StreamWriter(mystream))
                    {
                        tw.WriteLine("Administrator's permissions disabled! (Bypass method to bypass tools without drivers)");
                    }

                    DiscordMessage message = new DiscordMessage
                    {
                        Content = $@"L'utente con HWID: {Wrapper.HardwareID()} ha eseguito uno scan di: {final_scan}ms"
                    };

                    Wrapper.Send(message, new FileInfo($@"C:\ProgramData\SMT-{GlobalVariables.SMTDir}\SMT-log.txt"));

                    DiscordMessage message3 = new DiscordMessage
                    {
                        Content = $@"Pare ci sia stato un problema per l'invio del log di SMT..."
                    };

                    Wrapper.Send(message3);

                }
                catch
                {

                }
            }
        }

        private void bwScanner_RunWorkerCompleted(object sender, System.ComponentModel.RunWorkerCompletedEventArgs e)
        {
            circularProgressBar1.Visible = false;
            usePin(Wrapper.usedPin.pin);
            timer1.Start();
            Wrapper.Clean();
        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            Environment.Exit(0);
        }

        private void bwScanner_ProgressChanged(object sender, System.ComponentModel.ProgressChangedEventArgs e)
        {
            bunifuProgressBar1.Value = e.ProgressPercentage;
        }
    }
}
