using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using Newtonsoft.Json;

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
        PopulateDataGrid();
    }

    private void InitializeComponents()
    {
        this.Text = "Simple Password Manager";
        this.Width = 600;
        this.Height = 400;

        dataGridView = new DataGridView { Dock = DockStyle.Fill };
        dataGridView.Columns.Add("Service", "Service");
        dataGridView.Columns.Add("Username", "Username");
        dataGridView.Columns.Add("Password", "Password");
        this.Controls.Add(dataGridView);

        var addButton = new Button { Text = "Add New", Dock = DockStyle.Top };
        addButton.Click += AddNewEntry;
        this.Controls.Add(addButton);

        var deleteButton = new Button { Text = "Delete Selected", Dock = DockStyle.Top };
        deleteButton.Click += DeleteEntry;
        this.Controls.Add(deleteButton);

        this.FormClosing += OnClosing;
    }

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
        catch (FileNotFoundException)
        {
            return GenerateSalt();
        }
        catch
        {
            return GenerateSalt();
        }
    }

    private byte[] GenerateSalt()
    {
        return new byte[16]; // You can use a cryptographically secure random salt generator if desired.
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
                return JsonConvert.DeserializeObject<List<PasswordEntry>>(decryptedData);
            }
        }
        catch (FileNotFoundException)
        {
            return new List<PasswordEntry>();
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
            return Convert.ToBase64String(pbkdf2.GetBytes(32)); // 256-bit key
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
        var encryptedData = EncryptData(JsonConvert.SerializeObject(data), key);

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

    private void AddNewEntry(object sender, EventArgs e)
    {
        var addEntryForm = new Form();
        addEntryForm.Text = "Add New Entry";

        var serviceBox = new TextBox { Dock = DockStyle.Top };
        var usernameBox = new TextBox { Dock = DockStyle.Top };
        var passwordBox = new TextBox { Dock = DockStyle.Top, PasswordChar = '*' };

        addEntryForm.Controls.Add(serviceBox);
        addEntryForm.Controls.Add(usernameBox);
        addEntryForm.Controls.Add(passwordBox);

        var saveButton = new Button { Text = "Save", Dock = DockStyle.Bottom };
        saveButton.Click += (s, args) =>
        {
            if (!string.IsNullOrEmpty(serviceBox.Text) && !string.IsNullOrEmpty(usernameBox.Text) && !string.IsNullOrEmpty(passwordBox.Text))
            {
                data.Add(new PasswordEntry
                {
                    Service = serviceBox.Text,
                    Username = usernameBox.Text,
                    Password = passwordBox.Text
                });
                PopulateDataGrid();
                addEntryForm.Close();
            }
            else
            {
                MessageBox.Show("All fields are required.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        };

        addEntryForm.Controls.Add(saveButton);
        addEntryForm.ShowDialog();
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
