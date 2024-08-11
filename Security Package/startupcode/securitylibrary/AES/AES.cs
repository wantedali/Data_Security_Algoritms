using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        int[,] sBox = new int[,]
{
    { 99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118 },
    { 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192 },
    { 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21 },
    { 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117 },
    { 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132 },
    { 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207 },
    { 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168 },
    { 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210 },
    { 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115 },
    { 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219 },
    { 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121 },
    { 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8 },
    { 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138 },
    { 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158 },
    { 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223 },
    { 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22 }
};

        int[,] rCon = new int[,]
        {
    { 1, 2, 4, 8, 16, 32, 64, 128, 27, 54},
    { 0, 0, 0, 0, 0,  0,  0,   0,  0,  0 },
    { 0, 0, 0, 0, 0,  0,  0,   0,  0,  0},
    { 0, 0, 0, 0, 0,  0,  0,   0,  0,  0},

        };

        int[,] sBoxInv = new int[,]
{
    { 82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251 },
    { 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203 },
    { 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78 },
    { 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37 },
    { 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146 },
    { 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132 },
    { 144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6 },
    { 208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107 },
    { 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115 },
    { 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110 },
    { 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27 },
    { 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244 },
    { 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95 },
    { 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239 },
    { 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97 },
    { 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125 }
};

        //Decrypt algorithm
        public override string Decrypt(string cipherText, string key)
        {
            int[] cipherBytes = HexStringToByteArray(cipherText);
            int[] keyBytes = HexStringToByteArray(key);
            int[] keyByte = HexStringToByteArray(key);

            string s = "";
            // Generate round keys for decryption
            for (int i = 0; i <= 9; i++)
            {
                keyBytes = keyschedule(keyBytes, i);
            }
            // Initial round: AddRoundKey
            int[] add = addround(cipherBytes, keyBytes);
            int[,] admat;
            int[] z;
            int[] keyBytesinv;
            s = ByteArrayToHexString(add);
            //Console.WriteLine(s);

            // Rounds 1 to 9: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns
            for (int h = 9; h > 0; h--)
            {

                admat = ToMatrix(add);
                InvShiftRows(admat);
                add = FromMatrix(admat);
                s = ByteArrayToHexString(add);
                //Console.WriteLine(s);

                z = HexStringToarray(s);
                add = InvSubBytes(add, z);
                s = ByteArrayToHexString(add);
                //Console.WriteLine(s);

                keyBytesinv = HexStringToByteArray(key);
                for (int j = 0; j < h; j++)
                {
                    keyBytesinv = keyschedule(keyBytesinv, j);
                }
                add = addround(keyBytesinv, add);
                s = ByteArrayToHexString(add);
                //Console.WriteLine(s);
                admat = ToMatrix(add);
                InverseMixColumns(admat);
                add = FromMatrix(admat);
                s = ByteArrayToHexString(add);
                //Console.WriteLine(s);


            }

            // Final round: InvShiftRows, InvSubBytes, AddRoundKey
            admat = ToMatrix(add);
            InvShiftRows(admat);
            add = FromMatrix(admat);
            s = ByteArrayToHexString(add);

            s = ByteArrayToHexString(add);
            z = HexStringToarray(s);
            add = InvSubBytes(add, z);
            s = ByteArrayToHexString(add);

            //cipherBytes = AddRoundKey(cipherBytes, roundKeys[0]);
            add = addround(keyByte, add);
            s = ByteArrayToHexString(add);
            return s;
        }

        //Decrypt functions
        static void InverseMixColumns(int[,] state)
        {
            int[,] inverseMixColumnsMatrix = new int[,]
            {
        { 0x0E, 0x0B, 0x0D, 0x09 },
        { 0x09, 0x0E, 0x0B, 0x0D },
        { 0x0D, 0x09, 0x0E, 0x0B },
        { 0x0B, 0x0D, 0x09, 0x0E }
            };

            for (int col = 0; col < 4; col++)
            {
                int[] column = new int[4];
                // Copy the column into a temporary array
                for (int row = 0; row < 4; row++)
                {
                    column[row] = state[row, col];
                }

                // Perform matrix multiplication with the InverseMixColumns matrix
                state[0, col] = Multiply(0x0E, column[0]) ^ Multiply(0x0B, column[1]) ^ Multiply(0x0D, column[2]) ^ Multiply(0x09, column[3]);
                state[1, col] = Multiply(0x09, column[0]) ^ Multiply(0x0E, column[1]) ^ Multiply(0x0B, column[2]) ^ Multiply(0x0D, column[3]);
                state[2, col] = Multiply(0x0D, column[0]) ^ Multiply(0x09, column[1]) ^ Multiply(0x0E, column[2]) ^ Multiply(0x0B, column[3]);
                state[3, col] = Multiply(0x0B, column[0]) ^ Multiply(0x0D, column[1]) ^ Multiply(0x09, column[2]) ^ Multiply(0x0E, column[3]);
            }
        }
        int[] InvSubBytes(int[] x, int[] z)
        {
            int j = 0;
            for (int i = 0; i < z.Length; i += 2)
            {
                x[j] = sBoxInv[z[i], z[i + 1]];
                j++;
            }
            return x;
        }
        static void InvShiftRows(int[,] state)
        {
            // Second row shift right by 1
            int temp = state[1, 3];
            state[1, 3] = state[1, 2];
            state[1, 2] = state[1, 1];
            state[1, 1] = state[1, 0];
            state[1, 0] = temp;

            // Third row shift right by 2
            temp = state[2, 0];
            state[2, 0] = state[2, 2];
            state[2, 2] = temp;
            temp = state[2, 1];
            state[2, 1] = state[2, 3];
            state[2, 3] = temp;

            // Fourth row shift right by 3
            temp = state[3, 0];
            state[3, 0] = state[3, 1];
            state[3, 1] = state[3, 2];
            state[3, 2] = state[3, 3];
            state[3, 3] = temp;
        }

        //Encrypt algorithm
        public override string Encrypt(string plainText, string key)
        {
            int[] plainBytes = HexStringToByteArray(plainText);
            int[] keyBytes = HexStringToByteArray(key);


            int[] add = addround(plainBytes, keyBytes);
            string s = "";
            int[,] admat;
            int[] z;
            for (int h = 0; h < 9; h++)
            {
                s = ByteArrayToHexString(add);
                z = HexStringToarray(s);
                add = subbytes(add, z);
                s = ByteArrayToHexString(add);

                admat = ToMatrix(add);
                ShiftRows(admat);
                add = FromMatrix(admat);
                s = ByteArrayToHexString(add);


                MixColumns(admat);
                add = FromMatrix(admat);
                s = ByteArrayToHexString(add);

                keyBytes = keyschedule(keyBytes, h);
                add = addround(keyBytes, add);
                s = ByteArrayToHexString(add);

            }
            s = ByteArrayToHexString(add);
            z = HexStringToarray(s);
            add = subbytes(add, z);

            admat = ToMatrix(add);
            ShiftRows(admat);
            add = FromMatrix(admat);

            keyBytes = keyschedule(keyBytes, 9);
            add = addround(keyBytes, add);
            s = ByteArrayToHexString(add);
            return s;
        }

        //Encrypt functions
        int[] subbytes(int[] x, int[] z)
        {
            int j = 0;
            for (int i = 0; i < z.Length; i += 2)
            {
                x[j] = sBox[z[i], z[i + 1]];
                j++;
            }
            return x;
        }
        void ShiftRows(int[,] state)
        {
            // Second row shift left by 1
            int temp = state[1, 0];
            state[1, 0] = state[1, 1];
            state[1, 1] = state[1, 2];
            state[1, 2] = state[1, 3];
            state[1, 3] = temp;

            // Third row shift left by 2
            temp = state[2, 0];
            state[2, 0] = state[2, 2];
            state[2, 2] = temp;
            temp = state[2, 1];
            state[2, 1] = state[2, 3];
            state[2, 3] = temp;

            // Fourth row shift left by 3
            temp = state[3, 3];
            state[3, 3] = state[3, 2];
            state[3, 2] = state[3, 1];
            state[3, 1] = state[3, 0];
            state[3, 0] = temp;
        }
        void MixColumns(int[,] state)
        {
            int[,] temp = new int[4, 4];

            for (int c = 0; c < 4; c++)
            {
                temp[0, c] = Multiply(0x02, state[0, c]) ^ Multiply(0x03, state[1, c]) ^ state[2, c] ^ state[3, c];
                temp[1, c] = state[0, c] ^ Multiply(0x02, state[1, c]) ^ Multiply(0x03, state[2, c]) ^ state[3, c];
                temp[2, c] = state[0, c] ^ state[1, c] ^ Multiply(0x02, state[2, c]) ^ Multiply(0x03, state[3, c]);
                temp[3, c] = Multiply(0x03, state[0, c]) ^ state[1, c] ^ state[2, c] ^ Multiply(0x02, state[3, c]);
            }

            // Copy temp values back to state
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[i, j] = temp[i, j];
                }
            }
        }


        //Global functions
        int[] addround(int[] x, int[] z)
        {
            int[] res = new int[x.Length];
            for (int i = 0; i < x.Length; i++)
            {
                res[i] = x[i] ^ z[i];
            }
            return res;
        }
        int[] keyschedule(int[] x, int i = 0)
        {
            int[,] keymat = ToMatrix(x);
            int[] firstcol = { keymat[1, 3], keymat[2, 3], keymat[3, 3], keymat[0, 3] };
            string s = ByteArrayToHexString(firstcol);
            int[] z = HexStringToarray(s);
            firstcol = subbytes(firstcol, z);
            int[] firstcolinoldmat = { keymat[0, 0], keymat[1, 0], keymat[2, 0], keymat[3, 0] };
            int[] addrou = addround(firstcolinoldmat, firstcol);
            int[] rc = { rCon[0, i], 0, 0, 0 };
            addrou = addround(addrou, rc);
            s = ByteArrayToHexString(addrou);
            keymat[0, 0] = addrou[0];
            keymat[1, 0] = addrou[1];
            keymat[2, 0] = addrou[2];
            keymat[3, 0] = addrou[3];
            int[] firstcolinnewmat = { keymat[0, 0], keymat[1, 0], keymat[2, 0], keymat[3, 0] };
            int[] seccolinoldmat = { keymat[0, 1], keymat[1, 1], keymat[2, 1], keymat[3, 1] };
            addrou = addround(firstcolinnewmat, seccolinoldmat);
            keymat[0, 1] = addrou[0];
            keymat[1, 1] = addrou[1];
            keymat[2, 1] = addrou[2];
            keymat[3, 1] = addrou[3];
            int[] seccolinnewmat = { keymat[0, 1], keymat[1, 1], keymat[2, 1], keymat[3, 1] };
            int[] thirdoldmat = { keymat[0, 2], keymat[1, 2], keymat[2, 2], keymat[3, 2] };
            addrou = addround(thirdoldmat, seccolinnewmat);
            keymat[0, 2] = addrou[0];
            keymat[1, 2] = addrou[1];
            keymat[2, 2] = addrou[2];
            keymat[3, 2] = addrou[3];
            int[] thirdnewmat = { keymat[0, 2], keymat[1, 2], keymat[2, 2], keymat[3, 2] };
            int[] fourtholdmat = { keymat[0, 3], keymat[1, 3], keymat[2, 3], keymat[3, 3] };
            addrou = addround(fourtholdmat, thirdnewmat);
            keymat[0, 3] = addrou[0];
            keymat[1, 3] = addrou[1];
            keymat[2, 3] = addrou[2];
            keymat[3, 3] = addrou[3];
            x = FromMatrix(keymat);
            return x;
        }
        static int Multiply(int a, int b)
        {
            int result = 0;
            int highBit;

            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) == 1)
                {
                    result ^= a;
                }

                highBit = a & 0x80;
                a <<= 1;

                if (highBit == 0x80)
                {
                    a ^= 0x11B; // 0x11B represents x^8 + x^4 + x^3 + x + 1
                }

                b >>= 1;
            }

            return result;
        }
        static int[,] ToMatrix(int[] bytes)
        {
            int[,] matrix = new int[4, 4];
            int index = 0;
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    matrix[row, col] = bytes[index];
                    index++;
                }
            }
            return matrix;
        }
        static int[] FromMatrix(int[,] matrix)
        {
            int[] bytes = new int[16];
            int index = 0;
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    bytes[index] = matrix[row, col];
                    index++;
                }
            }
            return bytes;
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
        int[] HexStringToarray(string hex)
        {
            hex = hex.Replace("0x", "");
            int[] x = new int[hex.Length];
            for (int i = 0; i < hex.Length; i++)
            {
                x[i] = Convert.ToByte(hex.Substring(i, 1), 16);
            }

            return x;
        }
        string ByteArrayToHexString(int[] bytes)
        {
            StringBuilder hex = new StringBuilder(bytes.Length * 2);
            foreach (int b in bytes)
            {
                hex.AppendFormat("{0:x2}", b);
            }
            return "0x" + hex.ToString().ToUpper();
        }
    }
}
