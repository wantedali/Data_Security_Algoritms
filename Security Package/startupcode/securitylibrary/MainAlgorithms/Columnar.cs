using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            int numRows = 0;
            int numCols = 0;
            int counter = 0;
            cipherText = cipherText.ToLower();


            List<int> key = new List<int>(numCols);

            for (int i = 2; i < 8; i++)
            {

                if (plainText.Length % i == 0)
                {
                    numCols = i;
                }
            }

            numRows = plainText.Length / numCols;

            char[,] plain = new char[numRows, numCols];
            char[,] cipher = new char[numRows, numCols];

            for (int i = 0; i < numRows; i++)
            {
                for (int j = 0; j < numCols; j++)
                {
                    if (counter < plainText.Length)

                    {
                        plain[i, j] = plainText[counter];
                        counter++;
                    }
                }
            }

            counter = 0;

            for (int i = 0; i < numCols; i++)
            {

                for (int j = 0; j < numRows; j++)
                {
                    if (counter < plainText.Length)
                    {
                        cipher[j, i] = cipherText[counter];
                        counter++;
                    }
                }
            }

            int check = 0;

            for (int i = 0; i < numCols; i++)
            {
                for (int k = 0; k < numCols; k++)
                {
                    for (int j = 0; j < numRows; j++)
                    {
                        if (plain[j, i] == cipher[j, k])
                        {
                            check++;
                        }
                        if (check == numRows)
                            key.Add(k + 1);
                    }
                    check = 0;
                }
            }

            if (key.Count == 0)
            {
                for (int i = 0; i < numCols + 2; i++)
                {
                    key.Add(0);
                }
            }

            return key;

        }

        public string Decrypt(string cipherText, List<int> key)
        {
            String plainText = "";
            int charindex = 0;

            int numCols = key.Count;
            int numRows = (int)Math.Ceiling((double)cipherText.Length / numCols);


            char[,] data = new char[numRows, numCols];
            for (int i = 0; i < numCols; i++)
            {
                int keyindex = key.IndexOf(i + 1);

                for (int j = 0; j < numRows; j++)
                {
                    if (charindex < cipherText.Length)
                    {
                        data[j, keyindex] = cipherText[charindex];
                    }
                    else
                    {
                        data[j, keyindex] = 'X';
                    }
                    charindex++;

                }

            }
            for (int i = 0; i < numRows; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {

                    plainText += data[i, j];

                }
            }
            return plainText;
        }



        public string Encrypt(string plainText, List<int> key)
        {
            String cipherText = "";
            int numCols = key.Count;
            int numRows = (int)Math.Ceiling((double)plainText.Length / numCols);

            char[,] data = new char[numRows, numCols];

            int index = 0;

            for (int i = 0; i < numRows; i++)
            {
                for (int j = 0; j < numCols; j++)
                {
                    if (index < plainText.Count())

                        data[i, j] = plainText[index++];
                    else
                        break;
                }
            }
            for (int i = 1; i <= numCols; i++)
            {
                int keyindex = key.IndexOf(i);

                for (int j = 0; j < numRows; j++)
                {
                    if (data[j, keyindex] == '\0') continue;
                    cipherText += data[j, keyindex];
                }
            }
            return cipherText;
        }
    }
}


