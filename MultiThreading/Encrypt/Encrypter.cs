using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace MultiThreading.Encrypt
{
    public class Encrypter
    {
        public static string Encrypt(string clearText)
        {
            string EncryptionKey = "E178";
            byte[] clearBytles = Encoding.Unicode.GetBytes(clearText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = rfc.GetBytes(32);
                encryptor.IV = rfc.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream crypt = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        crypt.Write(clearBytles, 0, clearBytles.Length);
                        crypt.Close();
                    }
                    clearText = Convert.ToBase64String(ms.ToArray());
                }
            }
            return clearText;
        }
        public static string Decrypt(string text)
        {
            string EncryptionKey = "E178";
            text = text.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(text);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = rfc.GetBytes(32);
                encryptor.IV = rfc.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream crypt = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        crypt.Write(cipherBytes, 0, cipherBytes.Length);
                        crypt.Close();
                    }
                    text = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return text;
        }

    }
}
