using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {

        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {

            throw new NotImplementedException();

        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            key = key.ToUpper().Replace("J", "I");
            char[,] Matrix = new char[5, 5];
            string letters = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            string uniqueKey = new string(key.Distinct().ToArray());
            string remainingLetters = new string(letters.Except(uniqueKey).ToArray());
            string combinedKey = uniqueKey + remainingLetters;

            int counter = 0;
            for (int row = 0; row < 5; row++)
            {
                for (int col = 0; col < 5; col++)
                {
                    Matrix[row, col] = combinedKey[counter];
                    counter++;
                }
            }

            cipherText = cipherText.ToUpper().Replace("J", "I");
            string decryptedText = "";

            for (int i = 0; i < cipherText.Length; i += 2)
            {
                char char1 = cipherText[i];
                char char2 = cipherText[i + 1];

                int row1 = 0, col1 = 0, row2 = 0, col2 = 0;
                for (int row = 0; row < 5; row++)
                {
                    for (int col = 0; col < 5; col++)
                    {
                        if (Matrix[row, col] == char1)
                        {
                            row1 = row;
                            col1 = col;
                        }
                        if (Matrix[row, col] == char2)
                        {
                            row2 = row;
                            col2 = col;
                        }
                    }
                }

                if (row1 == row2)
                {
                    decryptedText += Matrix[row1, (col1 + 4) % 5];
                    decryptedText += Matrix[row2, (col2 + 4) % 5];
                }
                else if (col1 == col2)
                {
                    decryptedText += Matrix[(row1 + 4) % 5, col1];
                    decryptedText += Matrix[(row2 + 4) % 5, col2];
                }
                else
                {
                    decryptedText += Matrix[row1, col2];
                    decryptedText += Matrix[row2, col1];
                }
            }

            if (decryptedText[decryptedText.Length - 1] == 'X')
            {
                decryptedText = decryptedText.Remove(decryptedText.Length - 1, 1);
            }

            int cnt = 0;

            for (int i = 0; i < decryptedText.Length - 1; i++)
            {
                if (decryptedText[i] == 'X' && (i + cnt) % 2 == 1)
                {
                    if (decryptedText[i + 1] == decryptedText[i - 1])
                    {
                        decryptedText = decryptedText.Remove(i, 1);
                        i--;
                        cnt++;
                    }
                }

            }



            return decryptedText;
        }






        public string Encrypt(string plainText, string key)
        {


            key = key.ToUpper().Replace("J", "I");
            char[,] Matrix = new char[5, 5];
            string letters = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            string uniqueKey = new string(key.Distinct().ToArray());
            string remainingLetters = new string(letters.Except(uniqueKey).ToArray());
            string combinedKey = uniqueKey + remainingLetters;

            int counter = 0;
            for (int row = 0; row < 5; row++)
            {
                for (int col = 0; col < 5; col++)
                {
                    Matrix[row, col] = combinedKey[counter];
                    counter++;
                }
            }

            plainText = plainText.ToUpper().Replace("J", "I");
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Insert(i + 1, "X");
                }
            }

            if (plainText.Length % 2 != 0)
            {
                plainText += "X";
            }

            string encryptedText = "";

            for (int i = 0; i < plainText.Length; i += 2)
            {
                char char1 = plainText[i];
                char char2 = plainText[i + 1];

                int row1 = 0, col1 = 0, row2 = 0, col2 = 0;
                for (int row = 0; row < 5; row++)
                {
                    for (int col = 0; col < 5; col++)
                    {
                        if (Matrix[row, col] == char1)
                        {
                            row1 = row;
                            col1 = col;
                        }
                        if (Matrix[row, col] == char2)
                        {
                            row2 = row;
                            col2 = col;
                        }
                    }
                }

                if (row1 == row2)
                {
                    encryptedText += Matrix[row1, (col1 + 1) % 5];
                    encryptedText += Matrix[row2, (col2 + 1) % 5];
                }
                else if (col1 == col2)
                {
                    encryptedText += Matrix[(row1 + 1) % 5, col1];
                    encryptedText += Matrix[(row2 + 1) % 5, col2];
                }
                else
                {
                    encryptedText += Matrix[row1, col2];
                    encryptedText += Matrix[row2, col1];
                }
            }

            return encryptedText;
        }
    }
}