using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        
        public override string Decrypt(string cipherText, string key)
        {
            return Encrypt(cipherText, key);
        }

        public override  string Encrypt(string plainText, string key)
        {
            int[] pi, ki;
            if (plainText[0] == '0' && plainText[1] == 'x')
            {
                pi = HexStringToByteArray(plainText);
                ki = HexStringToByteArray(key);
            }
            else
            {
                pi = stringtoarray(plainText);
                ki = stringtoarray(key);
            }

            int[] S = new int[256];
            int[] T = new int[256];
            for (int i = 0; i < 256; i++)
            {
                S[i] = i;
                T[i] = ki[i % ki.Length];
            }
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                int tmp = S[i];
                S[i] = S[j];
                S[j] = tmp;
            }
            int z = 0, c = 0, t = 0;
            j = 0;
            int[] k = new int[pi.Length];
            while (c < pi.Length)
            {
                z = (z + 1) % 256;
                j = (j + S[z]) % 256;
                int tmp = S[z];
                S[z] = S[j];
                S[j] = tmp;
                t = (S[z] + S[j]) % 256;
                k[c] = S[t];
                c++;
            }
            StringBuilder cipher = new StringBuilder();
            for (int i = 0; i < pi.Length; i++)
            {
                cipher.Append((char)(pi[i] ^ k[i]));
            }
            if (plainText[0] == '0' && plainText[1] == 'x')
            {
                return StringToHex(cipher.ToString());
            }
            else
            {
                return cipher.ToString();
            }

        }
        int[] stringtoarray(string si)
        {
            int[] x = new int[si.Length];
            for(int i=0; i < x.Length; i++)
            {
                x[i]= si[i];
            }
            return x;
        }
        string StringToHex(string input)
        {
            StringBuilder sb = new StringBuilder("0x");
            foreach (char c in input)
            {
                string hex = ((int)c).ToString("x2");
                sb.Append(hex.TrimStart('0'));
            }
            return sb.ToString();
        }
        int[] HexStringToByteArray(string hex)
        {
            hex = hex.Replace("0x", "");
            int[] x = new int[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
            {
                x[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return x;
        }


        
    }
}
