using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            for (int key = 2; key < plainText.Length; key++)
            {
                string cipher = Encrypt(plainText, key);
                if (cipher.Equals(cipherText, StringComparison.InvariantCultureIgnoreCase))
                {
                    return key;
                }
            }
            return -1;
        }

        public string Decrypt(string cipherText, int key)
        {
            int depth = key;
            float plainTextLen = 0;
            int iterator = 0;
            string decryption = "";

            foreach (char c in cipherText)
            {
                if (c != ' ')
                {
                    plainTextLen++;
                }
            }

            int colNumber = (int)Math.Ceiling(plainTextLen / key);
            char[,] railMatrix = new char[depth, colNumber];

            for (int i = 0; i < depth; i++)
            {
                for (int j = 0; j < colNumber; j++)
                {
                    if (iterator == plainTextLen)
                    {
                        break;
                    }
                    else
                    {
                        char c = cipherText[iterator];
                        railMatrix[i, j] = c;
                    }

                    iterator++;
                }
            }
            for (int j = 0; j < colNumber; j++)
            {
                for (int i = 0; i < depth; i++)
                {
                    decryption += railMatrix[i, j];
                }
            }

            return decryption;
        }

        public string Encrypt(string plainText, int key)
        {
            int depth = key;
            float plainTextLen = 0;
            int iterator = 0;
            string encryption = "";

            foreach (char c in plainText)
            {
                if (c != ' ')
                {
                    plainTextLen++;
                }
            }

            int colNumber = (int)Math.Ceiling(plainTextLen / key);
            char[,] railMatrix = new char[depth, colNumber];

            for (int j = 0; j < colNumber; j++)
            {
                for (int i = 0; i < depth; i++)
                {
                    if (iterator == plainTextLen)
                    {
                        break;
                    }
                    else
                    {
                        char c = plainText[iterator];
                        railMatrix[i, j] = c;
                    }

                    iterator++;
                }
            }
            for (int i = 0; i < depth; i++)
            {
                for (int j = 0; j < colNumber; j++)
                {
                    encryption += railMatrix[i, j];
                }
            }

            return encryption;
        }
    }
}
