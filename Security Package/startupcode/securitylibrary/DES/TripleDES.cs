using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    /// 


    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public DES des = new DES();
        public string Decrypt(string cipherText, List<string> key)
        {
            string k1 = key[0];
            string k2 = key[1];
            string ans1 = des.Decrypt(cipherText, k1);
            string ans2 = des.Encrypt(ans1, k2);
            string ans3 = des.Decrypt(ans2, k1);
            return ans3;

            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, List<string> key)
        {
            string k1 = key[0];
            string k2 = key[1];
            string ans1 = des.Encrypt(plainText, k1);
            string ans2 = des.Decrypt(ans1, k2);
            string ans3 = des.Encrypt(ans2, k1);
            return ans3;
            // throw new NotImplementedException();
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}