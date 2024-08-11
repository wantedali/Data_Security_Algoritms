using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        string[] toBin =
        {
            "0000","0001","0010","0011","0100","0101","0110","0111",
            "1000","1001","1010","1011","1100","1101","1110","1111"
        };
        int[] LeftShifts = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        int[] PC1 =
        {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        };
        int[] PC2 =
      {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };
        int[] IP =
        {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };
        int[] Ematrix =
        {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        };
        int[] P =
        {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
        };
        int[] IPinverse =
        {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        };
        int[,] SBoxes =
        {
            {
                14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
            },
            {
                15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
            },
            {
                10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
            },
            {
                7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
            },
            {
                2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
            },
            {
                12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
            },
            {
                4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
            },
            {
                13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
            }
        };


        char xor(char x, char y)
        {
            if ((x == '0' && y == '1') || (x == '1' && y == '0'))
            {
                return '1';
            }
            else
            {
                return '0';
            }
        }

        int to_int_2(string input)
        {
            switch (input)
            {
                case "00":
                    return 0;
                    break;
                case "01":
                    return 1;
                    break;
                case "10":
                    return 2;
                    break;
                default:
                    return 3;
                    break;
            }
        }

        int to_int_4(string input)
        {
            switch (input)
            {
                case "0000":
                    return 0;
                    break;
                case "0001":
                    return 1;
                    break;
                case "0010":
                    return 2;
                    break;
                case "0011":
                    return 3;
                    break;
                case "0100":
                    return 4;
                    break;
                case "0101":
                    return 5;
                    break;
                case "0110":
                    return 6;
                    break;
                case "0111":
                    return 7;
                    break;
                case "1000":
                    return 8;
                    break;
                case "1001":
                    return 9;
                    break;
                case "1010":
                    return 10;
                    break;
                case "1011":
                    return 11;
                    break;
                case "1100":
                    return 12;
                    break;
                case "1101":
                    return 13;
                    break;
                case "1110":
                    return 14;
                    break;
                default:
                    return 15;
                    break;
            }

        }

        char toHEX(string input)
        {
            switch (input)
            {
                case "0000":
                    return '0';
                    break;
                case "0001":
                    return '1';
                    break;
                case "0010":
                    return '2';
                    break;
                case "0011":
                    return '3';
                    break;
                case "0100":
                    return '4';
                    break;
                case "0101":
                    return '5';
                    break;
                case "0110":
                    return '6';
                    break;
                case "0111":
                    return '7';
                    break;
                case "1000":
                    return '8';
                    break;
                case "1001":
                    return '9';
                    break;
                case "1010":
                    return 'A';
                    break;
                case "1011":
                    return 'B';
                    break;
                case "1100":
                    return 'C';
                    break;
                case "1101":
                    return 'D';
                    break;
                case "1110":
                    return 'E';
                    break;
                default:
                    return 'F';
                    break;
            }
        }

        public override string Decrypt(string cipherText, string key)
        {
            int e = 0;
            int r = 0;
            int a = 1;

            string plainText = String.Empty;
            StringBuilder binaryKey = new StringBuilder();

            for (int m = 2; m < key.Length; m++)
            {
                binaryKey.Append(toBin[int.Parse(key[m].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);
            }

            StringBuilder PC1key = new StringBuilder();

            foreach (int index in PC1)
            {
                PC1key.Append(binaryKey[index - 1]);
            }

            string[] C = new string[17];
            string[] D = new string[17];

            C[0] = PC1key.ToString().Substring(0, 28);
            D[0] = PC1key.ToString().Substring(28, 28);

            string shifted_C = C[0];
            string shifted_D = D[0];
            char last_bit;
            while (e < 16)
            {
                int j = 0;
                while (j < LeftShifts[e])
                {
                    last_bit = shifted_C[0];
                    shifted_C = shifted_C.Remove(0, 1);
                    shifted_C += last_bit;

                    last_bit = shifted_D[0];
                    shifted_D = shifted_D.Remove(0, 1);
                    shifted_D += last_bit;
                    j++;
                }
                C[e + 1] = shifted_C;
                D[e + 1] = shifted_D;
                e++;
            }
            StringBuilder[] roundKey = new StringBuilder[16];

            string[] K = new string[16];

            int len = K.Length;
            while (r < len)
            {
                K[r] = C[r + 1] + D[r + 1];
                r++;
            }

            int i = 0;
            while (i < len)
            {
                roundKey[i] = new StringBuilder();
                for (int j = 0; j < PC2.Length; j++)
                {
                    roundKey[i].Append(K[i][PC2[j] - 1]);
                }
                i++;
            }


            StringBuilder binaryCipherText = new StringBuilder();

            int re = 2;
            while (re < key.Length)
            {
                binaryCipherText.Append(toBin[int.Parse(cipherText[re].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);
                re++;
            }

            StringBuilder initialPermutation = new StringBuilder();

            for (int q = 0; q < IP.Length; q++)
            {
                initialPermutation.Append(binaryCipherText[IP[q] - 1]);
            }

            string[] L = new string[17];
            string[] R = new string[17];

            L[0] = initialPermutation.ToString().Substring(0, 32);
            R[0] = initialPermutation.ToString().Substring(32, 32);

            while (a < 17)
            {
                L[a] = R[a - 1];
                StringBuilder expandedR = new StringBuilder();
                StringBuilder xoroutput = new StringBuilder();
                StringBuilder sboxoutput = new StringBuilder();
                StringBuilder permutationOutput = new StringBuilder();

                for (int m = 0; m < Ematrix.Length; m++)
                {
                    expandedR.Append(R[a - 1][Ematrix[m] - 1]);
                }
                for (int n = 0; n < expandedR.Length; n++)
                {
                    xoroutput.Append(xor(expandedR[n], roundKey[15 - (a - 1)][n]));
                }

                int j = 0;
                while (j < 8)
                {
                    string Bn = xoroutput.ToString().Substring(6 * j, 6);
                    int row = to_int_2(Bn[0] + string.Empty + Bn[5]);
                    int column = to_int_4(Bn.Substring(1, 4));
                    sboxoutput.Append(toBin[SBoxes[j, (row * 16) + column]]);
                    j++;
                }
                for (int z = 0; z < P.Length; z++)
                {
                    permutationOutput.Append(sboxoutput[P[z] - 1]);
                }
                xoroutput = new StringBuilder();
                for (int y = 0; y < permutationOutput.Length; y++)
                {
                    xoroutput.Append(xor(L[a - 1][y], permutationOutput[y]));
                }
                R[a] = xoroutput.ToString();
                a++;
            }
            string finalCombination = R[16] + L[16];
            StringBuilder binaryPlainText = new StringBuilder();

            for (int p = 0; p < IPinverse.Length; p++)
            {
                binaryPlainText.Append(finalCombination[IPinverse[p] - 1]);
            }

            plainText += "0x";
            int x = 0;
            while (x < 16)
            {
                plainText += toHEX(binaryPlainText.ToString().Substring(4 * x, 4));
                x++;

            }
            return plainText;
        }

        public override string Encrypt(string plainText, string key)
        {
            string cipherText = String.Empty;
            int e = 0;
            int r = 0;
            int u = 0;
            int a = 1;

            StringBuilder binaryKey = new StringBuilder();

            for (int z = 2; z < key.Length; z++)
            {
                binaryKey.Append(toBin[int.Parse(key[z].ToString(), System.Globalization.NumberStyles.HexNumber)]);
            }

            StringBuilder PC1key = new StringBuilder();

            foreach (int index in PC1)
            {
                PC1key.Append(binaryKey[index - 1]);
            }

            string[] C = new string[17];
            string[] D = new string[17];

            C[0] = PC1key.ToString().Substring(0, 28);
            D[0] = PC1key.ToString().Substring(28, 28);

            string shifted_C = C[0];
            string shifted_D = D[0];
            char last_left_bit;

            while (e < 16)
            {
                int j = 0;
                while (j < LeftShifts[e])
                {
                    last_left_bit = shifted_C[0];
                    shifted_C = shifted_C.Remove(0, 1);
                    shifted_C += last_left_bit;

                    last_left_bit = shifted_D[0];
                    shifted_D = shifted_D.Remove(0, 1);
                    shifted_D += last_left_bit;
                    j++;
                }
                C[e + 1] = shifted_C;
                D[e + 1] = shifted_D;
                e++;
            }

            StringBuilder[] roundKey = new StringBuilder[16];

            string[] K = new string[16];

            int len = K.Length;
            while (r < len)
            {
                K[r] = C[r + 1] + D[r + 1];
                r++;
            }

            int i = 0;
            while (i < len)
            {
                roundKey[i] = new StringBuilder();
                for (int j = 0; j < PC2.Length; j++)
                {
                    roundKey[i].Append(K[i][PC2[j] - 1]);
                }
                i++;
            }

            StringBuilder binaryPlainText = new StringBuilder();

            for (int t = 2; t < key.Length; t++)
            {
                binaryPlainText.Append(toBin[int.Parse(plainText[t].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);
            }

            StringBuilder initialPermutation = new StringBuilder();

            for (int x = 0; x < IP.Length; x++)
            {
                initialPermutation.Append(binaryPlainText[IP[x] - 1]);
            }

            string[] L = new string[17];
            string[] R = new string[17];

            L[0] = initialPermutation.ToString().Substring(0, 32);
            R[0] = initialPermutation.ToString().Substring(32, 32);

            while (a < 17)
            {
                L[a] = R[a - 1];
                StringBuilder expandedR = new StringBuilder();
                StringBuilder xoroutput = new StringBuilder();
                StringBuilder sboxoutput = new StringBuilder();
                StringBuilder permutationOutput = new StringBuilder();

                for (int m = 0; m < Ematrix.Length; m++)
                {
                    expandedR.Append(R[a - 1][Ematrix[m] - 1]);
                }
                for (int n = 0; n < expandedR.Length; n++)
                {
                    xoroutput.Append(xor(expandedR[n], roundKey[a - 1][n]));
                }

                int j = 0;
                while (j < 8)
                {
                    string Bn = xoroutput.ToString().Substring(6 * j, 6);
                    int row = to_int_2(Bn[0] + string.Empty + Bn[5]);
                    int column = to_int_4(Bn.Substring(1, 4));
                    sboxoutput.Append(toBin[SBoxes[j, (row * 16) + column]]);
                    j++;
                }
                for (int z = 0; z < P.Length; z++)
                {
                    permutationOutput.Append(sboxoutput[P[z] - 1]);
                }
                xoroutput = new StringBuilder();
                for (int y = 0; y < permutationOutput.Length; y++)
                {
                    xoroutput.Append(xor(L[a - 1][y], permutationOutput[y]));
                }
                R[a] = xoroutput.ToString();
                a++;
            }

            string finalCombination = R[16] + L[16];
            StringBuilder binaryCipherText = new StringBuilder();
            for (int p = 0; p < IPinverse.Length; p++)
            {
                binaryCipherText.Append(finalCombination[IPinverse[p] - 1]);
            }

            cipherText += "0x";

            while (u < 16)
            {
                cipherText += toHEX(binaryCipherText.ToString().Substring(4 * u, 4));
                u++;
            }
            return cipherText;
        }
    }
}
    