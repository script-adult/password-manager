using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
Expand
message.txt
11 KB
﻿
k0PSNT
lovely._ella
k0psnt
A really big fucking hole coming right up! - Thermite
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using System.Text.Json;
using System.Drawing;

public class PasswordManagerApp : Form
{
    private const string FILENAME = "passwords.dat";
    private List<PasswordEntry> data = new List<PasswordEntry>();
    private string masterPassword;
    private byte[] salt;
    private DataGridView dataGridView;

    public PasswordManagerApp()
    {
        InitializeComponents();
        masterPassword = AskMasterPassword();
        if (masterPassword == null) return;

        salt = LoadSalt();
        data = LoadData(masterPassword);
        if (data != null)
            PopulateDataGrid();
    }

    private void InitializeComponents()
    {
        this.Text = "Simple Password Manager";
        this.Width = 600;
        this.Height = 400;

        dataGridView = new DataGridView
        {
            Dock = DockStyle.Fill,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill
        };
        dataGridView.Columns.Add("Service", "Service");
        dataGridView.Columns.Add("Username", "Username");
        dataGridView.Columns.Add("Password", "Password");
        this.Controls.Add(dataGridView);

        var buttonPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            FlowDirection = FlowDirection.LeftToRight,
            Height = 40,
            Padding = new Padding(10)
        };

        var addButton = new Button { Text = "Add New", Width = 100 };
        addButton.Click += AddNewEntry;

        var deleteButton = new Button { Text = "Delete Selected", Width = 120 };
        deleteButton.Click += DeleteEntry;

        buttonPanel.Controls.Add(addButton);
        buttonPanel.Controls.Add(deleteButton);
        this.Controls.Add(buttonPanel);

        this.FormClosing += OnClosing;
    }

    private void AddNewEntry(object sender, EventArgs e)
    {
        var addEntryForm = new Form
        {
            Text = "Add New Entry",
            Size = new Size(300, 220),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent
        };

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 4,
            Padding = new Padding(10),
            AutoSize = true
        };

        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 30));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 70));

        var lblService = new Label { Text = "Service:", Anchor = AnchorStyles.Right, AutoSize = true };
        var lblUsername = new Label { Text = "Username:", Anchor = AnchorStyles.Right, AutoSize = true };
        var lblPassword = new Label { Text = "Password:", Anchor = AnchorStyles.Right, AutoSize = true };

        var txtService = new TextBox { Dock = DockStyle.Fill };
        var txtUsername = new TextBox { Dock = DockStyle.Fill };
        var txtPassword = new TextBox { Dock = DockStyle.Fill, PasswordChar = '*' };

        var btnSave = new Button { Text = "Save", Dock = DockStyle.Fill };
        btnSave.Click += (s, args) =>
        {
            if (!string.IsNullOrWhiteSpace(txtService.Text) &&
                !string.IsNullOrWhiteSpace(txtUsername.Text) &&
                !string.IsNullOrWhiteSpace(txtPassword.Text))
            {
                data.Add(new PasswordEntry
                {
                    Service = txtService.Text,
                    Username = txtUsername.Text,
                    Password = txtPassword.Text
                });
                PopulateDataGrid();
                addEntryForm.Close();
            }
            else
            {
                MessageBox.Show("All fields are required.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        };

        layout.Controls.Add(lblService, 0, 0);
        layout.Controls.Add(txtService, 1, 0);
        layout.Controls.Add(lblUsername, 0, 1);
        layout.Controls.Add(txtUsername, 1, 1);
        layout.Controls.Add(lblPassword, 0, 2);
        layout.Controls.Add(txtPassword, 1, 2);
        layout.Controls.Add(btnSave, 0, 3);
        layout.SetColumnSpan(btnSave, 2);

        addEntryForm.Controls.Add(layout);
        addEntryForm.ShowDialog();
    }

    // The rest of the original code (no changes needed)...
    private string AskMasterPassword()
    {
        var passwordForm = new Form
        {
            Text = "Enter your Password",
            Width = 300,
            Height = 150
        };

        var passwordTextBox = new TextBox { PasswordChar = '*', Dock = DockStyle.Top };
        passwordForm.Controls.Add(passwordTextBox);

        var submitButton = new Button { Text = "Submit", Dock = DockStyle.Top };
        submitButton.Click += (sender, e) => { passwordForm.Close(); };
        passwordForm.Controls.Add(submitButton);

        passwordForm.ShowDialog();
        return passwordTextBox.Text;
    }

    private byte[] LoadSalt()
    {
        try
        {
            using (var reader = new BinaryReader(File.Open(FILENAME, FileMode.Open)))
            {
                var saltB64 = reader.ReadString();
                return Convert.FromBase64String(saltB64);
            }
        }
        catch
        {
            return GenerateSalt();
        }
    }

    private byte[] GenerateSalt()
    {
        return new byte[16];
    }

    private List<PasswordEntry> LoadData(string masterPassword)
    {
        try
        {
            using (var reader = new BinaryReader(File.Open(FILENAME, FileMode.Open)))
            {
                var saltB64 = reader.ReadString();
                var encryptedData = reader.ReadBytes((int)(reader.BaseStream.Length - reader.BaseStream.Position));

                var key = GenerateKey(masterPassword, Convert.FromBase64String(saltB64));
                var decryptedData = DecryptData(encryptedData, key);
                return JsonSerializer.Deserialize<List<PasswordEntry>>(decryptedData);
            }
        }
        catch
        {
            MessageBox.Show("Incorrect master password!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return null;
        }
    }

    private string GenerateKey(string masterPassword, byte[] salt)
    {
        using (var pbkdf2 = new Rfc2898DeriveBytes(masterPassword, salt, 100000))
        {
            return Convert.ToBase64String(pbkdf2.GetBytes(32));
        }
    }

    private byte[] EncryptData(string data, string key)
    {
        using (var aesAlg = Aes.Create())
        {
            aesAlg.Key = Convert.FromBase64String(key);
            aesAlg.GenerateIV();

            using (var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
            using (var msEncrypt = new MemoryStream())
            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            using (var writer = new StreamWriter(csEncrypt))
            {
                writer.Write(data);
                writer.Close();
                var encrypted = msEncrypt.ToArray();
                var result = new byte[aesAlg.IV.Length + encrypted.Length];
                Array.Copy(aesAlg.IV, 0, result, 0, aesAlg.IV.Length);
                Array.Copy(encrypted, 0, result, aesAlg.IV.Length, encrypted.Length);
                return result;
            }
        }
    }

    private string DecryptData(byte[] encryptedData, string key)
    {
        using (var aesAlg = Aes.Create())
        {
            aesAlg.Key = Convert.FromBase64String(key);
            var iv = new byte[aesAlg.BlockSize / 8];
            Array.Copy(encryptedData, 0, iv, 0, iv.Length);
            aesAlg.IV = iv;

            using (var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
            using (var msDecrypt = new MemoryStream(encryptedData, iv.Length, encryptedData.Length - iv.Length))
            using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            using (var reader = new StreamReader(csDecrypt))
            {
                return reader.ReadToEnd();
            }
        }
    }

    private void SaveData()
    {
        var key = GenerateKey(masterPassword, salt);
        var encryptedData = EncryptData(JsonSerializer.Serialize(data), key);

        using (var writer = new BinaryWriter(File.Open(FILENAME, FileMode.Create)))
        {
            writer.Write(Convert.ToBase64String(salt));
            writer.Write(encryptedData);
        }
    }

    private void PopulateDataGrid()
    {
        dataGridView.Rows.Clear();
        foreach (var entry in data)
        {
            dataGridView.Rows.Add(entry.Service, entry.Username, new string('*', entry.Password.Length));
        }
    }

    private void DeleteEntry(object sender, EventArgs e)
    {
        if (dataGridView.SelectedRows.Count > 0)
        {
            var row = dataGridView.SelectedRows[0];
            var service = row.Cells[0].Value.ToString();
            if (MessageBox.Show($"Are you sure you want to delete the entry for {service}?", "Confirm Delete", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            {
                data.RemoveAt(row.Index);
                PopulateDataGrid();
            }
        }
    }

    private void OnClosing(object sender, FormClosingEventArgs e)
    {
        if (masterPassword != null)
        {
            SaveData();
        }
    }

    public static void Main()
    {
        Application.Run(new PasswordManagerApp());
    }
}

public class PasswordEntry
{
    public string Service { get; set; }
    public string Username { get; set; }
    public string Password { get; set; }
}
