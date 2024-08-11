using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            //throw new NotImplementedException();
            int n=p*q,c=1;
            for(int i = 0; i < e; i++)
                c = (M * c) % n;
            return c;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            //throw new NotImplementedException();
            int eu = (p - 1) * (q - 1);
            ExtendedEuclid E=new ExtendedEuclid();
            int d = E.GetMultiplicativeInverse(e,eu);
            int n = p * q;
            int pt = 1;
            for(int i=0; i < d; i++)
            {
                pt = (C * pt) % n;
            }
            return pt;
        }


    }
}
