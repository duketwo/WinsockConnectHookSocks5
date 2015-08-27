namespace WSockConnectHook
{
    partial class MainForm
    {
        /// <summary>
        /// Erforderliche Designervariable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Verwendete Ressourcen bereinigen.
        /// </summary>
        /// <param name="disposing">True, wenn verwaltete Ressourcen gelöscht werden sollen; andernfalls False.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Vom Windows Form-Designer generierter Code

        /// <summary>
        /// Erforderliche Methode für die Designerunterstützung.
        /// Der Inhalt der Methode darf nicht mit dem Code-Editor geändert werden.
        /// </summary>
        private void InitializeComponent()
        {
        	this.logbox = new System.Windows.Forms.ListView();
        	this.columnHeader1 = new System.Windows.Forms.ColumnHeader();
        	this.SuspendLayout();
        	// 
        	// logbox
        	// 
        	this.logbox.AutoArrange = false;
        	this.logbox.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
        	        	        	this.columnHeader1});
        	this.logbox.Location = new System.Drawing.Point(12, 12);
        	this.logbox.Name = "logbox";
        	this.logbox.Size = new System.Drawing.Size(909, 353);
        	this.logbox.TabIndex = 140;
        	this.logbox.UseCompatibleStateImageBehavior = false;
        	this.logbox.View = System.Windows.Forms.View.Details;
        	// 
        	// columnHeader1
        	// 
        	this.columnHeader1.Text = "Logbox";
        	this.columnHeader1.Width = 1526;
        	// 
        	// MainForm
        	// 
        	this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
        	this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
        	this.ClientSize = new System.Drawing.Size(929, 378);
        	this.Controls.Add(this.logbox);
        	this.Name = "MainForm";
        	this.Text = "WSockConnectHook";
        	this.ResumeLayout(false);
        }

        #endregion

        private System.Windows.Forms.ListView logbox;
        private System.Windows.Forms.ColumnHeader columnHeader1;
    }
}

