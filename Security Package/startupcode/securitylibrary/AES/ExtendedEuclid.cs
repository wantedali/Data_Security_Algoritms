using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //throw new NotImplementedException();
            int[] A = new int[3] { 1, 0, baseN };
            int[] B = new int[3] { 0, 1, number };
            int q;

            while (true)
            {
                if (B[2] == 0 || B[2] == 1)
                {
                    break;
                }
                q = A[2] / B[2];

                for (int i = 0; i < 3; i++)
                {
                    int[] temp = new int[3];
                    temp[i] = B[i];

                    B[i] = (A[i]) - q * B[i];

                    A[i] = temp[i];
                }

            }
            if (B[2] == 1)
            {
                if (B[1] < 0)
                {
                    while (B[1] < 0)
                    {
                        B[1] = B[1] + baseN;
                    }
                }
                return B[1];
            }
            else
            {
                return -1;
            }
        }
    }
}
