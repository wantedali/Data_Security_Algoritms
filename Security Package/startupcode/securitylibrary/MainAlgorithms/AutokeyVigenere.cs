using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            Dictionary<Tuple<char, char>, char> vigenere = new Dictionary<Tuple<char, char>, char>();
            char a = 'A';
            for (char i = 'a'; i <= 'z'; i++)
            {
                int h = 0;
                for (char j = 'a'; j <= 'z'; h++, j++)
                {
                    int y = (i - 32) - a;
                    int g = y + h;
                    char x = (char)(a + ((g) % 26));
                    vigenere[Tuple.Create(i, x)] = j;


                }
            }
            string key_stream = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                key_stream += vigenere[Tuple.Create(plainText[i], cipherText[i])];
            }
            int siz = key_stream.Length, k = 0;
            bool ex = false;
            for (int i = 2; i < key_stream.Length - 1; i++)
            {
                if (key_stream[i] == plainText[k])
                {
                    if (!ex)
                    {
                        siz = i;
                        ex = true;
                    }


                    k++;
                }
                else
                {
                    k = 0;
                    siz = key_stream.Length;
                    ex = false;
                }
            }

            return key_stream.Substring(0, siz);
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            int size = cipherText.Length;
            string key_stream = key;
            int mod = size % key.Length;
            int div = size / key.Length;
            /*for (int i = 0; i < div - 1; i++)
            {
                key_stream += ;
            }
            for (int i = 0; i < mod; i++)
            {
                key_stream += key[i];
            }*/

            Dictionary<Tuple<char, char>, char> vigenere = new Dictionary<Tuple<char, char>, char>();
            char a = 'A';
            for (char i = 'a'; i <= 'z'; i++)
            {
                int h = 0;
                for (char j = 'a'; j <= 'z'; h++, j++)
                {
                    int y = (i - 32) - a;
                    int g = y + h;
                    char x = (char)(a + ((g) % 26));
                    vigenere[Tuple.Create(i, x)] = j;


                }
            }
            string plain = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                plain += vigenere[Tuple.Create(key_stream[i], cipherText[i])];
                key_stream += vigenere[Tuple.Create(key_stream[i], cipherText[i])];
            }

            return plain;
        }

        public string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            int size = plainText.Length;
            string key_stream = key;
            int mod = size % key.Length;
            int div = size / key.Length;

            for (int i = 0; i < div - 1; i++)
            {
                key_stream += plainText;
            }
            for (int i = 0; i < mod; i++)
            {
                key_stream += plainText[i];
            }

            Dictionary<Tuple<char, char>, char> vigenere = new Dictionary<Tuple<char, char>, char>();
            char a = 'a', b = 'a';
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    char h = (char)(a + j);
                    char y = (char)(b + i);
                    char x = (char)(a + ((i + j) % 26));
                    vigenere[Tuple.Create(h, y)] = x;
                }
            }
            string cipherr = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                cipherr += vigenere[Tuple.Create(plainText[i], key_stream[i])];
            }
            return cipherr;
        }
    }
}
