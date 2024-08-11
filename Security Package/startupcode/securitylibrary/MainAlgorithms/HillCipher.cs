using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public static int GCD(int A, int B)
        {
            int R;
            if (B == 0)
                return A;
            if (A > B)
            {
                R = A % B;

                A = B;

                B = R;
            }
            else
            {
                R = A % B;

                A = R;

                B = A;

            }


            return GCD(A, B);
        }
        public List<int> Analyse(List<int> PlainText, List<int> cipherText)
        {
            int kcol = PlainText.Count / 2, krow = 2, det;
            int col = cipherText.Count / 2;
            int[,] p = new int[krow, col];
            int[,] pi = new int[krow, col];
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    p[i, j] = -1;
                    pi[i, j] = -1;
                }
            }


            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    //if the plain text is not complete matrix
                    p[i, j] = cipherText[i + (j * krow)];
                    pi[i, j] = PlainText[i + (j * krow)];
                }

            }
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    //fill the the vector with X if the plain text is not complete matrix
                    if (p[i, j] == -1 || pi[i, j] == -1)
                    {
                        p[i, j] = 23;
                        p[i, j] = 23;
                    }
                }
            }
            int[,] ki = new int[2, 2];
            int l = 0;
            for (int a = 0; a < 26; a++)
            {
                for (int b = 0; b < 26; b++)
                {
                    for (int c = 0; c < 26; c++)
                    {
                        for (int d = 0; d < 26; d++)
                        {
                            ki[0, 0] = a; ki[0, 1] = b;
                            ki[1, 0] = c; ki[1, 1] = d;
                            int sum = 0;
                            int[,] ct = new int[2, col];
                            for (int i = 0; i < 2; i++)
                            {
                                for (int j = 0; j < col; j++)
                                {
                                    sum = 0;
                                    for (int jk = 0; jk < 2; jk++)
                                    {
                                        // get the multiplied matrix
                                        sum += ki[i, jk] * pi[jk, j];

                                    }
                                    ct[i, j] = sum % 26;
                                }
                            }
                            for (int i = 0; i < 2; i++)
                            {
                                for (int j = 0; j < col; j++)
                                {
                                    if (ct[i, j] == p[i, j])
                                    {
                                        l++;
                                    }
                                    else
                                    {
                                        l = 0;
                                    }
                                }
                            }
                            if (l == cipherText.Count)
                            {
                                break;
                            }

                        }
                        if (l == cipherText.Count)
                        {
                            break;
                        }
                    }
                    if (l == cipherText.Count)
                    {
                        break;
                    }
                }
                if (l == cipherText.Count)
                {
                    break;
                }
            }
            if (l < cipherText.Count)
            {
                throw new InvalidAnlysisException();
            }
            List<int> key = new List<int>();
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    key.Add(ki[i, j]);
                }
            }

            return key;

           


        }

        public string Analyse(string plainText, string cipherText)
        {
            char[] ar = new char[26];
            Dictionary<char, int> mp = new Dictionary<char, int>();

            // Initialize array and map for Hill Cipher
            for (int i = 0; i < 26; i++)
            {
                ar[i] = (char)('a' + i);
                mp[(char)('a' + i)] = i;
            }

            int kcol = plainText.Length / 2, krow = 2;
            int col = cipherText.Length / 2;
            int[,] p = new int[krow, col];
            int[,] pi = new int[krow, col];
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    p[i, j] = -1;
                    pi[i, j] = -1;
                }
            }


            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    //if the plain text is not complete matrix
                    p[i, j] = mp[cipherText[i + (j * krow)]];
                    pi[i, j] = mp[plainText[i + (j * krow)]];
                }

            }
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    //fill the the vector with X if the plain text is not complete matrix
                    if (p[i, j] == -1 || pi[i, j] == -1)
                    {
                        p[i, j] = 23;
                        pi[i, j] = 23;
                    }
                }
            }
            int[,] ki = new int[2, 2];
            int l = 0;
            for (int a = 0; a < 26; a++)
            {
                for (int b = 0; b < 26; b++)
                {
                    for (int c = 0; c < 26; c++)
                    {
                        for (int d = 0; d < 26; d++)
                        {
                            ki[0, 0] = a; ki[0, 1] = b;
                            ki[1, 0] = c; ki[1, 1] = d;
                            int sum = 0;
                            int[,] ct = new int[2, col];
                            for (int i = 0; i < 2; i++)
                            {
                                for (int j = 0; j < col; j++)
                                {
                                    sum = 0;
                                    for (int jk = 0; jk < 2; jk++)
                                    {
                                        // get the multiplied matrix
                                        sum += ki[i, jk] * pi[jk, j];

                                    }
                                    ct[i, j] = sum % 26;
                                }
                            }
                            for (int i = 0; i < 2; i++)
                            {
                                for (int j = 0; j < col; j++)
                                {
                                    if (ct[i, j] == p[i, j])
                                    {
                                        l++;
                                    }
                                    else
                                    {
                                        l = 0;
                                    }
                                }
                            }
                            if (l == cipherText.Length)
                            {
                                break;
                            }

                        }
                        if (l == cipherText.Length)
                        {
                            break;
                        }
                    }
                    if (l == cipherText.Length)
                    {
                        break;
                    }
                }
                if (l == cipherText.Length)
                {
                    break;
                }
            }
            if (l < cipherText.Length)
            {
                throw new InvalidAnlysisException();
            }
            StringBuilder ctt = new StringBuilder();
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    ctt.Append(ar[ki[i, j]]);
                }
            }
            string key = ctt.ToString();
            return key;
        }
        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {

            List<int> PlainText = plain3;
            List<int> cipherText = cipher3;

            int kcol = PlainText.Count / 3, krow = PlainText.Count / 3, det;
            det = PlainText[0] * (PlainText[4] * PlainText[8] - PlainText[7] * PlainText[5]) - PlainText[3] * (PlainText[1] * PlainText[8] - PlainText[7] * PlainText[2]) + PlainText[6] * (PlainText[1] * PlainText[5] - PlainText[2] * PlainText[4]);
            if (det >= 0)
            {
                det %= 26;
            }
            else
            {
                while (true)
                {
                    det += 26;
                    if (det % 26 >= 0)
                    {
                        det %= 26;
                        break;
                    }
                }
            }
            if (GCD(26, det) != 1 || det == 0)
            {
                throw new InvalidAnlysisException();
            }
            int b = 1;
            while (true)
            {
                if (det * b % 26 == 1)
                {
                    break;
                }
                b++;
            }
            List<int> key = PlainText;
            int[] ki = new int[PlainText.Count];
            ki[0] = 1 * (key[4] * key[8] - key[5] * key[7]);
            ki[3] = -1 * (key[1] * key[8] - key[2] * key[7]);
            ki[6] = 1 * (key[1] * key[5] - key[2] * key[4]);
            ki[1] = -1 * (key[3] * key[8] - key[6] * key[5]);
            ki[4] = 1 * (key[0] * key[8] - key[2] * key[6]);
            ki[7] = -1 * (key[0] * key[5] - key[3] * key[2]);
            ki[2] = 1 * (key[3] * key[7] - key[4] * key[6]);
            ki[5] = -1 * (key[0] * key[7] - key[1] * key[6]);
            ki[8] = 1 * (key[4] * key[0] - key[1] * key[3]);
            for (int i = 0; i < ki.Length; i++)
            {
                ki[i] = ki[i] * b;
                if (ki[i] >= 0)
                {
                    ki[i] %= 26;
                }
                else
                {
                    while (true)
                    {
                        ki[i] += 26;
                        if (ki[i] % 26 >= 0)
                        {
                            ki[i] %= 26;
                            break;
                        }
                    }
                }
            }
            int[,] keystream = new int[krow, kcol];
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < kcol; j++)
                {
                    keystream[j, i] = ki[i + (j * kcol)];
                }
            }

            int col = cipherText.Count / kcol;
            int[,] p = new int[krow, col];
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    p[i, j] = -1;
                }
            }


            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    //if the plain text is not complete matrix
                    p[i, j] = cipherText[i + (j * krow)];
                }

            }
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    //fill the the vector with X if the plain text is not complete matrix
                    if (p[i, j] == -1)
                    {
                        p[i, j] = 23;
                    }
                }
            }

            int[,] c = new int[krow, col];
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    // initialize the multiplied matrix with 0
                    c[i, j] = 0;

                }
            }
            int sum = 0;
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    sum = 0;
                    for (int jk = 0; jk < krow; jk++)
                    {
                        // get the multiplied matrix
                        sum += (p[i, jk] * keystream[jk, j]); ;
                    }
                    c[i, j] = sum % 26;
                }
            }
            List<int> ct = new List<int>();
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < krow; j++)
                {
                    ct.Add(c[i, j]);
                }
            }
            return ct;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            string plainText = plain3;
            string CipherText = cipher3;
            char[] ar = new char[26];
            Dictionary<char, int> mp = new Dictionary<char, int>();

            // Initialize array and map for Hill Cipher
            for (int i = 0; i < 26; i++)
            {
                ar[i] = (char)('a' + i);
                mp[(char)('a' + i)] = i;
            }
            List<int> PlainText = new List<int>();
            for (int i = 0; i < plainText.Length; i++)
            {
                PlainText.Add(mp[plainText[i]]);

            }

            List<int> cipherText = new List<int>();
            for (int i = 0; i < CipherText.Length; i++)
            {
                cipherText.Add(mp[CipherText[i]]);

            }

            int kcol = PlainText.Count / 3, krow = PlainText.Count / 3, det;
            det = PlainText[0] * (PlainText[4] * PlainText[8] - PlainText[7] * PlainText[5]) - PlainText[3] * (PlainText[1] * PlainText[8] - PlainText[7] * PlainText[2]) + PlainText[6] * (PlainText[1] * PlainText[5] - PlainText[2] * PlainText[4]);
            if (det >= 0)
            {
                det %= 26;
            }
            else
            {
                while (true)
                {
                    det += 26;
                    if (det % 26 >= 0)
                    {
                        det %= 26;
                        break;
                    }
                }
            }
            if (GCD(26, det) != 1 || det == 0)
            {
                throw new InvalidAnlysisException();
            }
            int b = 1;
            while (true)
            {
                if (det * b % 26 == 1)
                {
                    break;
                }
                b++;
            }
            List<int> key = PlainText;
            int[] pi = new int[PlainText.Count];
            pi[0] = 1 * (key[4] * key[8] - key[5] * key[7]);
            pi[3] = -1 * (key[1] * key[8] - key[2] * key[7]);
            pi[6] = 1 * (key[1] * key[5] - key[2] * key[4]);
            pi[1] = -1 * (key[3] * key[8] - key[6] * key[5]);
            pi[4] = 1 * (key[0] * key[8] - key[2] * key[6]);
            pi[7] = -1 * (key[0] * key[5] - key[3] * key[2]);
            pi[2] = 1 * (key[3] * key[7] - key[4] * key[6]);
            pi[5] = -1 * (key[0] * key[7] - key[1] * key[6]);
            pi[8] = 1 * (key[4] * key[0] - key[1] * key[3]);
            for (int i = 0; i < pi.Length; i++)
            {
                pi[i] = pi[i] * b;
                if (pi[i] >= 0)
                {
                    pi[i] %= 26;
                }
                else
                {
                    while (true)
                    {
                        pi[i] += 26;
                        if (pi[i] % 26 >= 0)
                        {
                            pi[i] %= 26;
                            break;
                        }
                    }
                }
            }
            int[,] keystream = new int[krow, kcol];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    keystream[j, i] = pi[i + (j * kcol)];
                }
            }

            int col = cipherText.Count / kcol;
            int[,] p = new int[krow, col];
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    p[i, j] = -1;
                }
            }


            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    //if the plain text is not complete matrix
                    p[i, j] = cipherText[i + (j * krow)];
                }

            }
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    //fill the the vector with X if the plain text is not complete matrix
                    if (p[i, j] == -1)
                    {
                        p[i, j] = 23;
                    }
                }
            }

            int[,] c = new int[krow, col];
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    // initialize the multiplied matrix with 0
                    c[i, j] = 0;

                }
            }
            int sum = 0;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    sum = 0;
                    for (int jk = 0; jk < 3; jk++)
                    {
                        // get the multiplied matrix
                        sum += (p[i, jk] * keystream[jk, j]); ;
                    }
                    c[i, j] = sum % 26;
                }
            }
            StringBuilder ctt = new StringBuilder();
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    ctt.Append(ar[c[i, j]]);
                }
            }
            string k = ctt.ToString();
            return k;
        }
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {

            int kcol, krow, det;
            int[] ki = new int[key.Count];
            if (key.Count == 4)
            {
                kcol = key.Count / 2;
                krow = key.Count / 2;
                det = ((key[0] * key[3]) - (key[1] * key[2]));

                int sw = key[0];
                ki[0] = key[3];
                ki[1] = -key[1];
                ki[2] = -key[2];
                ki[3] = sw;

            }
            else
            {
                kcol = key.Count / 3;
                krow = key.Count / 3;
                det = (key[0] * (key[4] * key[8] - key[5] * key[7]) - key[1] * (key[3] * key[8] - key[5] * key[6]) + key[2] * (key[3] * key[7] - key[4] * key[6]));



            }
            if (det >= 0)
            {
                det %= 26;
            }
            else
            {
                while (true)
                {
                    det += 26;
                    if (det % 26 >= 0)
                    {
                        det %= 26;
                        break;
                    }
                }
            }
            int b = 1;
            if (GCD(26, det) == 1)
            {
                while (true)
                {
                    if (det * b % 26 == 1)
                    {
                        break;
                    }
                    b++;
                }

            }
            else
            {
                throw new InvalidAnlysisException();
            }

            if (key.Count == 9)
            {
                ki[0] = 1 * (key[4] * key[8] - key[5] * key[7]);
                ki[1] = -1 * (key[3] * key[8] - key[5] * key[6]);
                ki[2] = 1 * (key[3] * key[7] - key[4] * key[6]);
                ki[3] = -1 * (key[1] * key[8] - key[2] * key[7]);
                ki[4] = 1 * (key[0] * key[8] - key[2] * key[6]);
                ki[5] = -1 * (key[0] * key[7] - key[1] * key[6]);
                ki[6] = 1 * (key[1] * key[5] - key[2] * key[4]);
                ki[7] = -1 * (key[0] * key[5] - key[2] * key[3]);
                ki[8] = 1 * (key[4] * key[0] - key[1] * key[3]);

            }

            for (int i = 0; i < ki.Length; i++)
            {
                ki[i] = ki[i] * b;
                if (ki[i] >= 0)
                {
                    ki[i] %= 26;
                }
                else
                {
                    while (true)
                    {
                        ki[i] += 26;
                        if (ki[i] % 26 >= 0)
                        {
                            ki[i] %= 26;
                            break;
                        }
                    }
                }
            }
            int[,] keystream = new int[krow, kcol];
            if (key.Count == 4)
            {        // take 1d array swap it to 2d array
                for (int i = 0; i < krow; i++)
                {
                    for (int j = 0; j < kcol; j++)
                    {
                        keystream[j, i] = ki[i + (j * kcol)];
                    }
                }

            }
            else
            {
                // take 1d array swap it to 2d array
                for (int i = 0; i < krow; i++)
                {
                    for (int j = 0; j < kcol; j++)
                    {
                        keystream[i, j] = ki[i + (j * kcol)];
                    }
                }
            }
            int col = cipherText.Count / kcol;
            int[,] p = new int[krow, col];
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    p[i, j] = -1;
                }
            }


            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    //if the plain text is not complete matrix
                    p[i, j] = cipherText[i + (j * krow)];


                }

            }
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    //fill the the vector with X if the plain text is not complete matrix
                    if (p[i, j] == -1)
                    {
                        p[i, j] = 23;
                    }
                }
            }
            int[,] c = new int[krow, col];
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    // initialize the multiplied matrix with 0
                    c[i, j] = 0;

                }
            }
            int sum = 0;
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    sum = 0;
                    for (int jk = 0; jk < krow; jk++)
                    {
                        // get the multiplied matrix
                        sum += (keystream[i, jk] * p[jk, j]);
                    }
                    c[i, j] = sum % 26;
                }
            }
            List<int> ct = new List<int>();
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < krow; j++)
                {
                    ct.Add(c[j, i]);
                }
            }
            return ct;
        }

        public string Decrypt(string cipherText, string ke)
        {

            //throw new NotImplementedException();
            char[] ar = new char[26];
            Dictionary<char, int> mp = new Dictionary<char, int>();

            // Initialize array and map for Hill Cipher
            for (int i = 0; i < 26; i++)
            {
                ar[i] = (char)('a' + i);
                mp[(char)('a' + i)] = i;
            }
            StringBuilder sb = new StringBuilder();
            foreach (char f in cipherText)
            {
                if ((f >= 'A' && f <= 'Z') || (f >= 'a' && f <= 'z'))
                {
                    sb.Append(char.ToLower(f));
                }
            }
            cipherText = sb.ToString();
            List<int> key = new List<int>();
            for (int i = 0; i < ke.Length; i++)
            {
                key.Add(mp[ke[i]]);
            }
            int kcol, krow, det;
            int[] ki = new int[key.Count];
            if (key.Count == 4)
            {
                kcol = key.Count / 2;
                krow = key.Count / 2;
                det = ((key[0] * key[3]) - (key[1] * key[2]));

                int sw = key[0];
                ki[0] = key[3];
                ki[1] = -key[1];
                ki[2] = -key[2];
                ki[3] = sw;

            }
            else
            {
                kcol = key.Count / 3;
                krow = key.Count / 3;
                det = (key[0] * (key[4] * key[8] - key[5] * key[7]) - key[1] * (key[3] * key[8] - key[5] * key[6]) + key[2] * (key[3] * key[7] - key[4] * key[6]));



            }
            if (det >= 0)
            {
                det %= 26;
            }
            else
            {
                while (true)
                {
                    det += 26;
                    if (det % 26 >= 0)
                    {
                        det %= 26;
                        break;
                    }
                }
            }
            int b = 1;
            if (GCD(26, det) == 1)
            {
                while (true)
                {
                    if (det * b % 26 == 1)
                    {
                        break;
                    }
                    b++;
                }

            }
            else
            {
                throw new InvalidAnlysisException();
            }

            if (key.Count == 9)
            {
                ki[0] = 1 * (key[4] * key[8] - key[5] * key[7]);
                ki[1] = -1 * (key[3] * key[8] - key[5] * key[6]);
                ki[2] = 1 * (key[3] * key[7] - key[4] * key[6]);
                ki[3] = -1 * (key[1] * key[8] - key[2] * key[7]);
                ki[4] = 1 * (key[0] * key[8] - key[2] * key[6]);
                ki[5] = -1 * (key[0] * key[7] - key[1] * key[6]);
                ki[6] = 1 * (key[1] * key[5] - key[2] * key[4]);
                ki[7] = -1 * (key[0] * key[5] - key[2] * key[3]);
                ki[8] = 1 * (key[4] * key[0] - key[1] * key[3]);

            }

            for (int i = 0; i < ki.Length; i++)
            {
                ki[i] = ki[i] * b;
                if (ki[i] >= 0)
                {
                    ki[i] %= 26;
                }
                else
                {
                    while (true)
                    {
                        ki[i] += 26;
                        if (ki[i] % 26 >= 0)
                        {
                            ki[i] %= 26;
                            break;
                        }
                    }
                }
            }
            int[,] keystream = new int[krow, kcol];
            if (key.Count == 4)
            {        // take 1d array swap it to 2d array
                for (int i = 0; i < krow; i++)
                {
                    for (int j = 0; j < kcol; j++)
                    {
                        keystream[j, i] = ki[i + (j * kcol)];
                    }
                }

            }
            else
            {
                // take 1d array swap it to 2d array
                for (int i = 0; i < krow; i++)
                {
                    for (int j = 0; j < kcol; j++)
                    {
                        keystream[i, j] = ki[i + (j * kcol)];
                    }
                }
            }
            int col = cipherText.Length / kcol;
            int[,] p = new int[krow, col];
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    p[i, j] = -1;
                }
            }


            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    //if the plain text is not complete matrix
                    p[i, j] = mp[cipherText[i + (j * krow)]];


                }

            }
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    //fill the the vector with X if the plain text is not complete matrix
                    if (p[i, j] == -1)
                    {
                        p[i, j] = 23;
                    }
                }
            }
            int[,] c = new int[krow, col];
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    // initialize the multiplied matrix with 0
                    c[i, j] = 0;

                }
            }
            int sum = 0;
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    sum = 0;
                    for (int jk = 0; jk < krow; jk++)
                    {
                        // get the multiplied matrix
                        sum += (keystream[i, jk] * p[jk, j]);
                    }
                    c[i, j] = sum % 26;
                }
            }
            StringBuilder ct = new StringBuilder();
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < krow; j++)
                {
                    ct.Append(ar[c[j, i]]);
                }
            }
            string plainText = ct.ToString();
            return plainText;

        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int[] k = key.ToArray();
            int kcol, krow;
            Console.WriteLine(key.Count);
            if (key.Count == 4)
            {
                kcol=krow = key.Count / 2;
               
            }
            else
            {
                kcol=krow = key.Count / 3;
                

            }
            int[,] keystream = new int[krow, kcol];
            // take 1d array swap it to 2d array
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < kcol; j++)
                {
                    keystream[j, i] = k[i + (j * kcol)];
                }
            }
            /* for (int i = 0; i < krow; i++)
             {
                 for (int j = 0; j < kcol; j++)
                 {
                     Console.Write(keystream[i, j]+" ");
                 }
                 Console.WriteLine();
             }*/
            int col = plainText.Count / kcol;
            int[,] p = new int[krow, col];
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    p[i, j] = -1;
                }
            }
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    //if the plain text is not complete matrix
                    p[i, j] = plainText[i + (j * krow)];


                }

            }
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    //fill the the vector with X if the plain text is not complete matrix
                    if (p[i, j] == -1)
                    {
                        p[i, j] = 23;
                    }
                }
            }
            /*  for (int i = 0; i < krow; i++)
              {
                  for (int j = 0; j < col; j++)
                  {
                      Console.Write(p[i, j] + " ");

              }
              Console.WriteLine();
          }*/
            int[,] c = new int[krow, col];
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    // initialize the multiplied matrix with 0
                    c[i, j] = 0;

                }
            }
            int sum = 0;
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    sum = 0;
                    for (int jk = 0; jk < krow; jk++)
                    {
                        // get the multiplied matrix
                        sum += (keystream[i, jk] * p[jk, j]);
                    }
                    c[i, j] = sum % 26;
                }
            }
            List<int> ct = new List<int>();
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < krow; j++)
                {
                    ct.Add(c[j, i]);
                }
            }
            return ct;

        }

        public string Encrypt(string plainText, string key)
        {

            char[] ar = new char[26];
            Dictionary<char, int> mp = new Dictionary<char, int>();

            // Initialize array and map for Hill Cipher
            for (int i = 0; i < 26; i++)
            {
                ar[i] = (char)('a' + i);
                mp[(char)('a' + i)] = i;
            }
            StringBuilder sb = new StringBuilder();
            foreach (char f in plainText)
            {
                if ((f >= 'A' && f <= 'Z') || (f >= 'a' && f <= 'z'))
                {
                    sb.Append(char.ToLower(f));
                }
            }
            string s2 = sb.ToString();
            int[] k = new int[key.Length];
            int kcol, krow;
            if (key.Length == 4)
            {
                kcol = key.Length / 2;
                krow = key.Length / 2;
            }
            else
            {
                kcol = key.Length / 3;
                krow = key.Length / 3;

            }

            // swap the  string key to array of numbers
            for (int i = 0; i < key.Length; i++)
            {
                k[i] = mp[key[i]];
            }
            int[,] keystream = new int[krow, kcol];
            // take 1d array swap it to 2d array
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < kcol; j++)
                {
                    keystream[j, i] = k[i + (j * kcol)];
                }
            }
            /* for (int i = 0; i < krow; i++)
             {
                 for (int j = 0; j < kcol; j++)
                 {
                     Console.Write(keystream[i, j]+" ");
                 }
                 Console.WriteLine();
             }*/
            int col = s2.Length / kcol;
            int[,] p = new int[krow, col];
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    p[i, j] = -1;
                }
            }
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    //if the plain text is not complete matrix
                    if ((s2[(i + (j * krow))] >= 65 && s2[(i + (j * krow))] <= 90) || (s2[(i + (j * krow))] >= 97 && s2[(i + (j * krow))] <= 122))
                    {
                        p[i, j] = mp[s2[(i + (j * krow))]];
                    }

                }

            }
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    //fill the the vector with X if the plain text is not complete matrix
                    if (p[i, j] == -1)
                    {
                        p[i, j] = 23;
                    }
                }
            }
            /*  for (int i = 0; i < krow; i++)
              {
                  for (int j = 0; j < col; j++)
                  {
                      Console.Write(p[i, j] + " ");

              }
              Console.WriteLine();
          }*/
            int[,] c = new int[krow, col];
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    // initialize the multiplied matrix with 0
                    c[i, j] = 0;

                }
            }
            int sum = 0;
            for (int i = 0; i < krow; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    sum = 0;
                    for (int jk = 0; jk < krow; jk++)
                    {
                        // get the multiplied matrix
                        sum += (keystream[i, jk] * p[jk, j]);
                    }
                    c[i, j] = sum % 26;
                }
            }
            StringBuilder ct = new StringBuilder();
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < krow; j++)
                {
                    ct.Append(ar[c[j, i]]);
                }
            }
            string cipherText = ct.ToString();
            return cipherText;
        }


    }
}
