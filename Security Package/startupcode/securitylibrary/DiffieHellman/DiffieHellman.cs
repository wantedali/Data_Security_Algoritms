using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //throw new NotImplementedException();
            List<int> keys = new List<int>();
            int pupa=1,pupb=1;
            for (int i = 0; i < xa; i++) 
            {
                pupa = (pupa * alpha) % q;
            }
            for (int i = 0; i < xb; i++)
            {
                pupb = (pupb * alpha) % q;
            }
            int seca = 1,secb=1;
            for (int i = 0; i < xa; i++)
            {
               secb = (secb * pupb) % q;
            }
            for (int i = 0; i < xb; i++)
            {
                seca = (seca * pupa) % q;
            }

            keys.Add(seca);
            keys.Add(secb);
            return keys;
        }
    }
}
