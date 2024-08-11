using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            Dictionary<char, char> dic = new Dictionary<char, char>();
            string key = "";

            char c = 'a';
            while (c <= 'z')
            {
                dic[c] = default;
                c++;
            }

            for (char i = 'a'; i < 'z'; i++)
            {
                for (int j = 0; j < plainText.Length; j++)
                {
                    if (i == plainText[j])
                    {
                        dic[i] = char.ToLower(cipherText[j]);
                    }
                }
            }

            foreach (var dicKey in dic.Keys.ToList())
            {
                if (dic[dicKey] == '\0')
                {
                    char newValue = 'a';
                    while (dic.ContainsValue(newValue))
                    {
                        newValue++;
                    }
                    dic[dicKey] = newValue;
                }
            }
            foreach (KeyValuePair<char, char> kvp in dic)
            {
                key += kvp.Value;
            }

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            Dictionary<char, char> dic = new Dictionary<char, char>();
            string decryption = "";

            char c = 'a';
            int itearator = 0;

            while (c <= 'z')
            {
                dic[c] = key[itearator];
                itearator++;
                c++;
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                foreach (KeyValuePair<char, char> kvp in dic)
                {
                    bool isEqual = char.ToLower(kvp.Value) == char.ToLower(cipherText[i]);
                    if (isEqual)
                    {
                        decryption += kvp.Key;
                    }
                }
            }
            return decryption;
        }

        public string Encrypt(string plainText, string key)
        {
            Dictionary<char, char> dic = new Dictionary<char, char>();
            string encryption = "";

            char c = 'a';
            int itearator = 0;

            while (c <= 'z')
            {
                dic[c] = key[itearator];
                itearator++;
                c++;
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                foreach (KeyValuePair<char, char> kvp in dic)
                {
                    bool isEqual = char.ToLower(kvp.Key) == char.ToLower(plainText[i]);
                    if (isEqual)
                    {
                        encryption += kvp.Value;
                    }
                }
            }
            return encryption;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {

            do
            {
                Dictionary<string, int> mp = new Dictionary<string, int>();
                bool notfound = true;
                for (int i = 0; i < cipher.Length; i++)
                {
                    for (int t = 0; t < mp.Count; t++)
                    {

                        var element = mp.ElementAt(t);
                        if (cipher[i].ToString() == element.Key)
                        {
                            mp[element.Key]++;
                            notfound = false;
                            break;
                        }
                        else
                        {
                            notfound = true;
                            continue;
                        }
                    }
                    if (notfound == true)
                    {
                        mp[cipher[i].ToString()] = 1;
                    }
                }
                string al = "etaoinsrhldcumfpgwybvkxjqz";
                string key = "";
                var oo_map = from entr in mp orderby entr.Value descending select entr;
                mp = oo_map.ToDictionary(o => o.Key, o => o.Value);
                for (int j = 0; j < cipher.Length; j++)
                {
                    int z = mp.Keys.ToList().IndexOf(cipher[j].ToString());
                    key += al[z];
                }
                return key;


            } while (false) ;


        }
    }
}
