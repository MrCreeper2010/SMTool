
namespace SMT
{
    partial class Auth
    {
        /// <summary>
        /// Variabile di progettazione necessaria.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Pulire le risorse in uso.
        /// </summary>
        /// <param name="disposing">ha valore true se le risorse gestite devono essere eliminate, false in caso contrario.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Codice generato da Progettazione Windows Form

        /// <summary>
        /// Metodo necessario per il supporto della finestra di progettazione. Non modificare
        /// il contenuto del metodo con l'editor di codice.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Auth));
            Bunifu.UI.WinForms.BunifuButton.BunifuButton.StateProperties stateProperties13 = new Bunifu.UI.WinForms.BunifuButton.BunifuButton.StateProperties();
            Bunifu.UI.WinForms.BunifuButton.BunifuButton.StateProperties stateProperties14 = new Bunifu.UI.WinForms.BunifuButton.BunifuButton.StateProperties();
            this.lblEnter = new System.Windows.Forms.Label();
            this.btnMinimize = new System.Windows.Forms.PictureBox();
            this.btnClose = new System.Windows.Forms.PictureBox();
            this.pbLogo = new System.Windows.Forms.PictureBox();
            this.txtPin = new Bunifu.UI.WinForms.BunifuTextbox.BunifuTextBox();
            this.btnStart = new Bunifu.UI.WinForms.BunifuButton.BunifuButton();
            this.bunifuFormDock1 = new Bunifu.UI.WinForms.BunifuFormDock();
            this.bwScanner = new System.ComponentModel.BackgroundWorker();
            this.timer1 = new System.Windows.Forms.Timer(this.components);
            this.label1 = new System.Windows.Forms.Label();
            this.circularProgressBar1 = new CircularProgressBar.CircularProgressBar();
            this.bunifuProgressBar1 = new Bunifu.UI.Winforms.BunifuProgressBar();
            ((System.ComponentModel.ISupportInitialize)(this.btnMinimize)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.btnClose)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.pbLogo)).BeginInit();
            this.SuspendLayout();
            // 
            // lblEnter
            // 
            this.lblEnter.AutoSize = true;
            this.lblEnter.Font = new System.Drawing.Font("Microsoft Sans Serif", 15.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblEnter.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(133)))), ((int)(((byte)(137)))), ((int)(((byte)(153)))));
            this.lblEnter.Location = new System.Drawing.Point(208, 200);
            this.lblEnter.Name = "lblEnter";
            this.lblEnter.Size = new System.Drawing.Size(127, 25);
            this.lblEnter.TabIndex = 1;
            this.lblEnter.Text = "Enter a pin";
            // 
            // btnMinimize
            // 
            this.btnMinimize.Cursor = System.Windows.Forms.Cursors.Hand;
            this.btnMinimize.Image = global::SMT.Properties.Resources.icons8_macos_riduci_a_icona_64;
            this.btnMinimize.Location = new System.Drawing.Point(459, 4);
            this.btnMinimize.Name = "btnMinimize";
            this.btnMinimize.Size = new System.Drawing.Size(30, 29);
            this.btnMinimize.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.btnMinimize.TabIndex = 5;
            this.btnMinimize.TabStop = false;
            this.btnMinimize.Click += new System.EventHandler(this.btnMinimize_Click);
            // 
            // btnClose
            // 
            this.btnClose.Cursor = System.Windows.Forms.Cursors.Hand;
            this.btnClose.Image = global::SMT.Properties.Resources.icons8_chiudi_macos_64;
            this.btnClose.Location = new System.Drawing.Point(490, 4);
            this.btnClose.Name = "btnClose";
            this.btnClose.Size = new System.Drawing.Size(30, 29);
            this.btnClose.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.btnClose.TabIndex = 4;
            this.btnClose.TabStop = false;
            this.btnClose.Click += new System.EventHandler(this.btnClose_Click);
            // 
            // pbLogo
            // 
            this.pbLogo.BackgroundImage = global::SMT.Properties.Resources.v2;
            this.pbLogo.Image = global::SMT.Properties.Resources.v2;
            this.pbLogo.Location = new System.Drawing.Point(173, 23);
            this.pbLogo.Name = "pbLogo";
            this.pbLogo.Size = new System.Drawing.Size(200, 173);
            this.pbLogo.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.pbLogo.TabIndex = 3;
            this.pbLogo.TabStop = false;
            // 
            // txtPin
            // 
            this.txtPin.AcceptsReturn = false;
            this.txtPin.AcceptsTab = false;
            this.txtPin.AutoCompleteMode = System.Windows.Forms.AutoCompleteMode.None;
            this.txtPin.AutoCompleteSource = System.Windows.Forms.AutoCompleteSource.None;
            this.txtPin.BackColor = System.Drawing.Color.White;
            this.txtPin.BackgroundImage = ((System.Drawing.Image)(resources.GetObject("txtPin.BackgroundImage")));
            this.txtPin.BorderColorActive = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(115)))), ((int)(((byte)(223)))));
            this.txtPin.BorderColorDisabled = System.Drawing.Color.FromArgb(((int)(((byte)(161)))), ((int)(((byte)(161)))), ((int)(((byte)(161)))));
            this.txtPin.BorderColorHover = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(115)))), ((int)(((byte)(223)))));
            this.txtPin.BorderColorIdle = System.Drawing.Color.FromArgb(((int)(((byte)(107)))), ((int)(((byte)(107)))), ((int)(((byte)(107)))));
            this.txtPin.BorderRadius = 1;
            this.txtPin.BorderThickness = 2;
            this.txtPin.CharacterCasing = System.Windows.Forms.CharacterCasing.Normal;
            this.txtPin.DefaultFont = new System.Drawing.Font("Segoe UI Semibold", 9.75F);
            this.txtPin.DefaultText = "";
            this.txtPin.FillColor = System.Drawing.Color.White;
            this.txtPin.HideSelection = true;
            this.txtPin.IconLeft = null;
            this.txtPin.IconLeftCursor = System.Windows.Forms.Cursors.Default;
            this.txtPin.IconPadding = 10;
            this.txtPin.IconRight = null;
            this.txtPin.IconRightCursor = System.Windows.Forms.Cursors.Default;
            this.txtPin.Location = new System.Drawing.Point(174, 230);
            this.txtPin.MaxLength = 6;
            this.txtPin.MinimumSize = new System.Drawing.Size(100, 35);
            this.txtPin.Modified = false;
            this.txtPin.Name = "txtPin";
            this.txtPin.PasswordChar = '●';
            this.txtPin.ReadOnly = false;
            this.txtPin.SelectedText = "";
            this.txtPin.SelectionLength = 0;
            this.txtPin.SelectionStart = 0;
            this.txtPin.ShortcutsEnabled = true;
            this.txtPin.Size = new System.Drawing.Size(200, 35);
            this.txtPin.Style = Bunifu.UI.WinForms.BunifuTextbox.BunifuTextBox._Style.Material;
            this.txtPin.TabIndex = 2;
            this.txtPin.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            this.txtPin.TextMarginLeft = 5;
            this.txtPin.TextPlaceholder = "";
            this.txtPin.UseSystemPasswordChar = true;
            // 
            // btnStart
            // 
            this.btnStart.BackColor = System.Drawing.Color.Transparent;
            this.btnStart.BackgroundImage = ((System.Drawing.Image)(resources.GetObject("btnStart.BackgroundImage")));
            this.btnStart.ButtonText = "Start Scan";
            this.btnStart.ButtonTextMarginLeft = 0;
            this.btnStart.Cursor = System.Windows.Forms.Cursors.Hand;
            this.btnStart.DisabledBorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(161)))), ((int)(((byte)(161)))), ((int)(((byte)(161)))));
            this.btnStart.DisabledFillColor = System.Drawing.Color.Gray;
            this.btnStart.DisabledForecolor = System.Drawing.Color.White;
            this.btnStart.Font = new System.Drawing.Font("Segoe UI Semibold", 9.75F);
            this.btnStart.ForeColor = System.Drawing.Color.White;
            this.btnStart.IconLeftCursor = System.Windows.Forms.Cursors.Hand;
            this.btnStart.IconPadding = 10;
            this.btnStart.IconRightCursor = System.Windows.Forms.Cursors.Hand;
            this.btnStart.IdleBorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(115)))), ((int)(((byte)(223)))));
            this.btnStart.IdleBorderRadius = 1;
            this.btnStart.IdleBorderThickness = 1;
            this.btnStart.IdleFillColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(115)))), ((int)(((byte)(223)))));
            this.btnStart.IdleIconLeftImage = null;
            this.btnStart.IdleIconRightImage = null;
            this.btnStart.Location = new System.Drawing.Point(211, 275);
            this.btnStart.Name = "btnStart";
            stateProperties13.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(85)))), ((int)(((byte)(166)))), ((int)(((byte)(221)))));
            stateProperties13.BorderRadius = 1;
            stateProperties13.BorderThickness = 1;
            stateProperties13.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(85)))), ((int)(((byte)(166)))), ((int)(((byte)(221)))));
            stateProperties13.ForeColor = System.Drawing.Color.White;
            stateProperties13.IconLeftImage = null;
            stateProperties13.IconRightImage = null;
            this.btnStart.onHoverState = stateProperties13;
            stateProperties14.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(40)))), ((int)(((byte)(96)))), ((int)(((byte)(144)))));
            stateProperties14.BorderRadius = 1;
            stateProperties14.BorderThickness = 1;
            stateProperties14.FillColor = System.Drawing.Color.FromArgb(((int)(((byte)(40)))), ((int)(((byte)(96)))), ((int)(((byte)(144)))));
            stateProperties14.ForeColor = System.Drawing.Color.White;
            stateProperties14.IconLeftImage = null;
            stateProperties14.IconRightImage = null;
            this.btnStart.OnPressedState = stateProperties14;
            this.btnStart.Size = new System.Drawing.Size(121, 40);
            this.btnStart.TabIndex = 0;
            this.btnStart.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.btnStart.Click += new System.EventHandler(this.btnStart_Click);
            // 
            // bunifuFormDock1
            // 
            this.bunifuFormDock1.AllowFormDragging = true;
            this.bunifuFormDock1.AllowFormDropShadow = true;
            this.bunifuFormDock1.AllowFormResizing = false;
            this.bunifuFormDock1.AllowHidingBottomRegion = true;
            this.bunifuFormDock1.AllowOpacityChangesWhileDragging = false;
            this.bunifuFormDock1.BorderOptions.BottomBorder.BorderColor = System.Drawing.Color.Silver;
            this.bunifuFormDock1.BorderOptions.BottomBorder.BorderThickness = 1;
            this.bunifuFormDock1.BorderOptions.BottomBorder.ShowBorder = true;
            this.bunifuFormDock1.BorderOptions.LeftBorder.BorderColor = System.Drawing.Color.Silver;
            this.bunifuFormDock1.BorderOptions.LeftBorder.BorderThickness = 1;
            this.bunifuFormDock1.BorderOptions.LeftBorder.ShowBorder = true;
            this.bunifuFormDock1.BorderOptions.RightBorder.BorderColor = System.Drawing.Color.Silver;
            this.bunifuFormDock1.BorderOptions.RightBorder.BorderThickness = 1;
            this.bunifuFormDock1.BorderOptions.RightBorder.ShowBorder = true;
            this.bunifuFormDock1.BorderOptions.TopBorder.BorderColor = System.Drawing.Color.Silver;
            this.bunifuFormDock1.BorderOptions.TopBorder.BorderThickness = 1;
            this.bunifuFormDock1.BorderOptions.TopBorder.ShowBorder = true;
            this.bunifuFormDock1.ContainerControl = this;
            this.bunifuFormDock1.DockingIndicatorsColor = System.Drawing.Color.FromArgb(((int)(((byte)(202)))), ((int)(((byte)(215)))), ((int)(((byte)(233)))));
            this.bunifuFormDock1.DockingIndicatorsOpacity = 0.5D;
            this.bunifuFormDock1.DockingOptions.DockAll = true;
            this.bunifuFormDock1.DockingOptions.DockBottomLeft = true;
            this.bunifuFormDock1.DockingOptions.DockBottomRight = true;
            this.bunifuFormDock1.DockingOptions.DockFullScreen = true;
            this.bunifuFormDock1.DockingOptions.DockLeft = true;
            this.bunifuFormDock1.DockingOptions.DockRight = true;
            this.bunifuFormDock1.DockingOptions.DockTopLeft = true;
            this.bunifuFormDock1.DockingOptions.DockTopRight = true;
            this.bunifuFormDock1.FormDraggingOpacity = 0.9D;
            this.bunifuFormDock1.ParentForm = this;
            this.bunifuFormDock1.ShowCursorChanges = false;
            this.bunifuFormDock1.ShowDockingIndicators = false;
            this.bunifuFormDock1.TitleBarOptions.AllowFormDragging = true;
            this.bunifuFormDock1.TitleBarOptions.BunifuFormDock = this.bunifuFormDock1;
            this.bunifuFormDock1.TitleBarOptions.DoubleClickToExpandWindow = true;
            this.bunifuFormDock1.TitleBarOptions.TitleBarControl = null;
            this.bunifuFormDock1.TitleBarOptions.UseBackColorOnDockingIndicators = false;
            // 
            // bwScanner
            // 
            this.bwScanner.WorkerReportsProgress = true;
            this.bwScanner.DoWork += new System.ComponentModel.DoWorkEventHandler(this.bwScanner_DoWork);
            this.bwScanner.ProgressChanged += new System.ComponentModel.ProgressChangedEventHandler(this.bwScanner_ProgressChanged);
            this.bwScanner.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(this.bwScanner_RunWorkerCompleted);
            // 
            // timer1
            // 
            this.timer1.Interval = 10000;
            this.timer1.Tick += new System.EventHandler(this.timer1_Tick);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(6, 324);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(60, 13);
            this.label1.TabIndex = 6;
            this.label1.Text = "SMT v1.13";
            // 
            // circularProgressBar1
            // 
            this.circularProgressBar1.AnimationFunction = WinFormAnimation.KnownAnimationFunctions.Liner;
            this.circularProgressBar1.AnimationSpeed = 500;
            this.circularProgressBar1.BackColor = System.Drawing.Color.Transparent;
            this.circularProgressBar1.Font = new System.Drawing.Font("Microsoft Sans Serif", 72F, System.Drawing.FontStyle.Bold);
            this.circularProgressBar1.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(64)))), ((int)(((byte)(64)))), ((int)(((byte)(64)))));
            this.circularProgressBar1.InnerColor = System.Drawing.Color.White;
            this.circularProgressBar1.InnerMargin = 2;
            this.circularProgressBar1.InnerWidth = -1;
            this.circularProgressBar1.Location = new System.Drawing.Point(243, 200);
            this.circularProgressBar1.MarqueeAnimationSpeed = 2000;
            this.circularProgressBar1.Name = "circularProgressBar1";
            this.circularProgressBar1.OuterColor = System.Drawing.Color.White;
            this.circularProgressBar1.OuterMargin = -25;
            this.circularProgressBar1.OuterWidth = 26;
            this.circularProgressBar1.ProgressColor = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(115)))), ((int)(((byte)(223)))));
            this.circularProgressBar1.ProgressWidth = 5;
            this.circularProgressBar1.SecondaryFont = new System.Drawing.Font("Microsoft Sans Serif", 36F);
            this.circularProgressBar1.Size = new System.Drawing.Size(63, 65);
            this.circularProgressBar1.StartAngle = 270;
            this.circularProgressBar1.Style = System.Windows.Forms.ProgressBarStyle.Marquee;
            this.circularProgressBar1.SubscriptColor = System.Drawing.Color.FromArgb(((int)(((byte)(166)))), ((int)(((byte)(166)))), ((int)(((byte)(166)))));
            this.circularProgressBar1.SubscriptMargin = new System.Windows.Forms.Padding(10, -35, 0, 0);
            this.circularProgressBar1.SubscriptText = "";
            this.circularProgressBar1.SuperscriptColor = System.Drawing.Color.FromArgb(((int)(((byte)(166)))), ((int)(((byte)(166)))), ((int)(((byte)(166)))));
            this.circularProgressBar1.SuperscriptMargin = new System.Windows.Forms.Padding(10, 35, 0, 0);
            this.circularProgressBar1.SuperscriptText = "";
            this.circularProgressBar1.TabIndex = 7;
            this.circularProgressBar1.TextMargin = new System.Windows.Forms.Padding(8, 8, 0, 0);
            this.circularProgressBar1.Value = 68;
            this.circularProgressBar1.Visible = false;
            // 
            // bunifuProgressBar1
            // 
            this.bunifuProgressBar1.Animation = 0;
            this.bunifuProgressBar1.AnimationStep = 10;
            this.bunifuProgressBar1.BackgroundImage = ((System.Drawing.Image)(resources.GetObject("bunifuProgressBar1.BackgroundImage")));
            this.bunifuProgressBar1.BorderColor = System.Drawing.Color.White;
            this.bunifuProgressBar1.BorderRadius = 5;
            this.bunifuProgressBar1.BorderThickness = 2;
            this.bunifuProgressBar1.Location = new System.Drawing.Point(135, 271);
            this.bunifuProgressBar1.MaximumValue = 100;
            this.bunifuProgressBar1.MinimumValue = 0;
            this.bunifuProgressBar1.Name = "bunifuProgressBar1";
            this.bunifuProgressBar1.ProgressBackColor = System.Drawing.Color.White;
            this.bunifuProgressBar1.ProgressColorLeft = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(115)))), ((int)(((byte)(223)))));
            this.bunifuProgressBar1.ProgressColorRight = System.Drawing.Color.FromArgb(((int)(((byte)(78)))), ((int)(((byte)(115)))), ((int)(((byte)(223)))));
            this.bunifuProgressBar1.Size = new System.Drawing.Size(284, 10);
            this.bunifuProgressBar1.TabIndex = 8;
            this.bunifuProgressBar1.Value = 0;
            // 
            // Auth
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.Color.White;
            this.ClientSize = new System.Drawing.Size(524, 343);
            this.Controls.Add(this.bunifuProgressBar1);
            this.Controls.Add(this.circularProgressBar1);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.pbLogo);
            this.Controls.Add(this.txtPin);
            this.Controls.Add(this.btnClose);
            this.Controls.Add(this.btnStart);
            this.Controls.Add(this.lblEnter);
            this.Controls.Add(this.btnMinimize);
            this.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(133)))), ((int)(((byte)(137)))), ((int)(((byte)(153)))));
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "Auth";
            this.Text = "SMT";
            this.Load += new System.EventHandler(this.Auth_Load);
            ((System.ComponentModel.ISupportInitialize)(this.btnMinimize)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.btnClose)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.pbLogo)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private Bunifu.UI.WinForms.BunifuButton.BunifuButton btnStart;
        private Bunifu.UI.WinForms.BunifuTextbox.BunifuTextBox txtPin;
        private System.Windows.Forms.Label lblEnter;
        private System.Windows.Forms.PictureBox pbLogo;
        private System.Windows.Forms.PictureBox btnClose;
        private System.Windows.Forms.PictureBox btnMinimize;
        private Bunifu.UI.WinForms.BunifuFormDock bunifuFormDock1;
        private System.ComponentModel.BackgroundWorker bwScanner;
        private System.Windows.Forms.Timer timer1;
        private System.Windows.Forms.Label label1;
        private CircularProgressBar.CircularProgressBar circularProgressBar1;
        private Bunifu.UI.Winforms.BunifuProgressBar bunifuProgressBar1;
    }
}

