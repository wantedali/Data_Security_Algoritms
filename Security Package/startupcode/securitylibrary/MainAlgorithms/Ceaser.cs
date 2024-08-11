using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            String ceaser = "abcdefghijklmnopqrstuvwxyz", ci = "";
            for (int l = 0; l < plainText.Length; l++)
            {
                for (int k = 0; k < 26; k++)
                {
                    if (plainText[l] == ceaser[k])
                    {
                        ci += ceaser[(k + key) % 26];

                    }


                }
            }

            return ci;
        }

        public string Decrypt(string cipherText, int key)
        {

            String ceaser = "abcdefghijklmnopqrstuvwxyz", pl = "";
            int k, l, cindx, val;
            cipherText = cipherText.ToLower();
            for (l = 0; l < cipherText.Length; l++)
            {
                for (k = 0; k < 26; k++)
                {
                    if (cipherText[l] == ceaser[k])
                        if (k >= key)
                        {
                            cindx = k;
                            val = (cindx - key) % 26;
                            pl += ceaser[val];
                        }
                        else
                        {
                            cindx = k;
                            val = 26 - (key - cindx);
                            pl += ceaser[val];

                        }
                }

            }
            return pl;
        }






        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            String ceaser = "abcdefghijklmnopqrstuvwxyz";
            int ky = 0, ci = 0, pl = 0;
            cipherText = cipherText.ToLower();
            for (int y = 0; y < 26; y++)
            {
                if (cipherText[0] == ceaser[y])
                { ci = y; }
            }
            for (int r = 0; r < 26; r++)
            {
                if (plainText[0] == ceaser[r])
                { pl = r; }
            }

            if (ci >= pl)
            {
                ky = (ci - pl) % 26;
            }
            else
            {
                ky = 26 - (pl - ci);
            }


            return ky;
        }

    }
}