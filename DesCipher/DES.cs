using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace DesCipher
{
    //https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
    public class DES
    {
        private byte[,] PC1 = new byte[,]
        {
            { 57, 49, 41, 33, 25, 17, 9 },
            { 1, 58, 50, 42, 34, 26, 18 },
            { 10, 2, 59, 51, 43, 35, 27 },
            { 19, 11, 3, 60, 52, 44, 36 },
            { 63, 55, 47, 39, 31, 23, 15},
            { 7, 62, 54, 46, 38, 30, 22 },
            { 14, 6, 61, 53, 45, 37 , 29 },
            { 21, 13, 5, 28, 20, 12, 4 }
        };


        private byte[,] PC2 = new byte[,]
        {
            { 14,17,11,24,1,5   },
            { 3,28,15,6,21,10   },
            { 23,19,12,4,26,8   },
            { 16,7,27,20,13,2   },
            { 41,52,31,37,47,55 },
            { 30,40,51,45,33,48 },
            { 44,49,39,56,34,53 },
            { 46,42,50,36,29,32 }
        };

        private  byte[,] IP = new byte[,]
        {
            {58, 50, 42, 34, 26, 18, 10, 2},
            {60, 52, 44, 36, 28, 20, 12, 4},
            {62, 54, 46, 38, 30, 22, 14, 6},
            {64, 56, 48, 40, 32, 24, 16, 8},
            {57, 49, 41, 33, 25, 17,  9, 1},
            {59, 51, 43, 35, 27, 19, 11, 3},
            {61, 53, 45, 37, 29, 21, 13, 5},
            {63, 55, 47, 39, 31, 23, 15, 7}
        };

        //IP-1
        private byte[,] IPneg = new byte[,]
        {
            {40,8,48,16,56,24,64,32},
            {39,7,47,15,55,23,63,31},
            {38,6,46,14,54,22,62,30},
            {37,5,45,13,53,21,61,29},
            {36,4,44,12,52,20,60,28},
            {35,3,43,11,51,19,59,27},
            {34,2,42,10,50,18,58,26},
            {33,1,41,9,49,17,57,25}
        };

        private byte[,] P = new byte[,]
        {
            {16,7,20,21},
            {29,12,28,17},
            {1,15,23,26},
            {5,18,31,10},
            {2,8,24,14},
            {32,27,3,9},
            {19,13,30,6},
            {22,11,4,25}
        };


        private byte[,] E = new byte[,]
        {
            {32,1,2,3,4,5},
            {4,5,6,7,8,9},
            {8,9,10,11,12,13},
            {12,13,14,15,16,17},
            {16,17,18,19,20,21},
            {20,21,22,23,24,25},
            {24,25,26,27,28,29},
            {28,29,30,31,32,1}
        };


        private byte[,,] Sboxes = new byte[,,]
        {
         /*S1*/
         {
            {14, 4, 13, 1, 2, 15, 11, 8, 3 ,10, 6 ,12, 5, 9, 0, 7},
            {0,15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
            {4,1, 14, 8, 13, 6, 2 ,11, 15 ,12, 9, 7, 3, 10, 5, 0},
            {15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14, 10, 0, 6 ,13}
        },
         /*S2*/
         {
            {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
            {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
            {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
            {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
        },
         /*S3*/
        {
            {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
            {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
            {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
            {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
        },
        /*S4*/
        {
            {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
            {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
            {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
            {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
        },
        /*S5*/
        {
          {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
          {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
          {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
          {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
        },
        /*S6*/
        {
          {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
          {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
          {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
          {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
        },
        /*S7*/
        {
           {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
           {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
           {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
           {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
        },
        /*S8*/
        {
            {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
            {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
            {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
            {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
        }
        };

        private List<byte[]> Keystates = new List<byte[]>();

        private byte[] key = new byte[8] { 0, 0, 0, 0, 0, 0, 0, 0 };

        public DES(byte[] key)
        {
            for(int i =0;i < this.key.Length;i++)
            {
                if (i < key.Length)
                    this.key[i] = key[i];
            }
        }

        public DES()
        {
            //Will use default key 0000000000000000
        }

        public void Init()
        {
            reverseByteArr(key);

            GenerateKeyStream();
        }

        protected void GenerateKeyStream()
        {
            byte[] pkey = new byte[7] { 0, 0, 0, 0, 0, 0, 0 };

            for (int i = 1, j = 0, k = 0; i < 57; i++)
            {
                if (k > 6)
                {
                    j++;
                    k = 0;
                }
                if (j >= 8) break;

                int index = PC1[j, k++];

                int bit = GetBit(key, index);

                SetBit(pkey, i, bit);
            }


            byte[] C = new byte[4];
            byte[] D = new byte[4];

            for (int i = 1; i <= 28; i++)
            {
                SetBit(C, i, GetBit(pkey, i));
            }

            for (int i = 28, m = 0; i <= 56; i++)
            {
                SetBit(D, m++, GetBit(pkey, i));
            }

            List<byte[]> Cstates = new List<byte[]>();
            List<byte[]> Dstates = new List<byte[]>();

            int leftShift = 2;

            for (int i = 1; i <= 16; i++)
            {
                if (i == 1 || i == 2 || i == 16 || i == 9) leftShift = 1;
                else leftShift = 2;

                for (int l = 0; l < leftShift; l++)
                {
                    rotateKeyBitsLeft(C);
                    rotateKeyBitsLeft(D);
                }

                byte[] newC = new byte[4];

                Array.Copy(C, newC, C.Length);

                byte[] newD = new byte[4];

                Array.Copy(D, newD, D.Length);

                Cstates.Add(newC);
                Dstates.Add(newD);
            }

            int count = 0;

            do
            {
                byte[] pkeyone = new byte[6];

                for (int i = 1, j = 0, k = 0; i <= 48; i++)
                {
                    if (k > 5)
                    {
                        j++;
                        k = 0;
                    }
                    if (j >= 8) break;

                    int index = PC2[j, k++];

                    if (index <= 28)
                    {
                        int bit = GetBit(Cstates[count], index);
                        SetBit(pkeyone, i, bit);
                    }
                    else
                    {
                        int bit = GetBit(Dstates[count], index - 28);
                        SetBit(pkeyone, i, bit);
                    }
                }

                Keystates.Add(pkeyone);
                count++;
            }
            while (count < 16);
        }

        public byte[] Encrypt(string input)
        {
            byte[] inputBytes = Encoding.ASCII.GetBytes(input);

            reverseByteArr(inputBytes);

            using (MemoryStream ms = new MemoryStream())
            {
                for (int i = 0; i < inputBytes.Length; i += 8)
                {
                    byte[] block = new byte[8] { 0, 0, 0, 0, 0, 0, 0, 0 };

                    for (int j = 0, k = 0; j < 8; j++)
                    {
                        if ((i + k) < inputBytes.Length)
                            block[j] = inputBytes[i + k++];
                    }

                    byte[] cipher = CryptBlock(block);

                    foreach (var b in cipher)
                    {
                        ms.WriteByte(b);
                    }
                }

                return ms.ToArray();
            }
        }

        public byte[] Encrypt(byte[] inputBytes)
        {
            reverseByteArr(inputBytes);

            using (MemoryStream ms = new MemoryStream())
            {
                for (int i = 0; i < inputBytes.Length; i += 8)
                {
                    byte[] block = new byte[8] { 0, 0, 0, 0, 0, 0, 0, 0 };

                    for (int j = 0, k = 0; j < 8; j++)
                    {
                        if ((i + k) < inputBytes.Length)
                            block[j] = inputBytes[i + k++];
                    }

                    byte[] cipher = CryptBlock(block);

                    foreach (var b in cipher)
                    {
                        ms.WriteByte(b);
                    }
                }

                return ms.ToArray();
            }
        }

        public byte[] Decrypt(byte[] inputBytes)
        {
            reverseByteArr(inputBytes);

            using (MemoryStream ms = new MemoryStream())
            {
                for (int i = 0; i < inputBytes.Length; i += 8)
                {
                    byte[] block = new byte[8] { 0, 0, 0, 0, 0, 0, 0, 0 };

                    for (int j = 0, k = 0; j < 8; j++)
                    {
                        if ((i + k) < inputBytes.Length)
                            block[j] = inputBytes[i + k++];
                    }

                    byte[] cipher = CryptBlock(block, false);

                    foreach (var b in cipher)
                    {
                        ms.WriteByte(b);
                    }
                }

                return ms.ToArray();
            }
        }

        public byte[] GetKey()
        {
            return this.key;
        }


        public List<byte[]> GetKeys()
        {
            return this.Keystates;
        }

        protected void reverseByteArr(byte[] arr)
        {
            for (int i = 0; i < arr.Length; i++)
            {
                arr[i] = reverseInt8(arr[i]);
            }
        }

        //Step2: Encode each 64-bit block of data
        protected byte[] CryptBlock(byte[] block, bool encrypt = true)
        {
            byte[] IPnew = new byte[8];

            List<byte[]> LArr = new List<byte[]>();
            List<byte[]> RArr = new List<byte[]>();

            for (int i = 1, k = 0, j = 0; i <= 64; i++)
            {
                if (k > 7)
                {
                    j++;
                    k = 0;
                }
                if (j >= 8) break;

                int index = IP[j, k++];

                int bit = GetBit(block, index);

                SetBit(IPnew, i, bit);
            }

            byte[] L0 = new byte[4];
            byte[] R0 = new byte[4];

            Array.Copy(IPnew, 0, L0, 0, 4);
            Array.Copy(IPnew, 4, R0, 0, 4);

            LArr.Add(L0);
            RArr.Add(R0);

            //for 1<=n<=16, using a function f which operates on two blocks--a data block of 32 bits and a key Kn of 48 bits--to produce a block of 32 bits.
            for (int m = 1; m <= 16; m++)
            {
                byte[] ER0 = new byte[6];

                for (int i = 1, k = 0, j = 0; i <= 48; i++)
                {
                    if (k > 5)
                    {
                        j++;
                        k = 0;
                    }
                    if (j >= 8) break;

                    int index = E[j, k++];

                    int bit = GetBit(RArr[m - 1], index);

                    SetBit(ER0, i, bit);
                }

                //K1+E(R0)
                byte[] xoredR0 = new byte[6];
                byte[] curKey = new byte[6];

                if (!encrypt) curKey = Keystates[16 - m];
                else curKey = Keystates[m - 1];

                for (int i = 0; i < 6; i++)
                {
                    xoredR0[i] = (byte)(curKey[i] ^ ER0[i]);
                }

                byte[] sOut = new byte[4];

                for (int i = 1, c = 1; i <= 48; i += 6)
                {
                    byte sRow = (byte)((GetBit(xoredR0, i) << 1) | (byte)(GetBit(xoredR0, i + 5)));
                    byte sColumn = (byte)((((GetBit(xoredR0, i + 1) << 1) | (byte)(GetBit(xoredR0, i + 2))) << 1) << 1 | ((byte)GetBit(xoredR0, i + 3) << 1 | (byte)GetBit(xoredR0, i + 4)));

                    byte num = Sboxes[c - 1, sRow, sColumn]; ;

                    if (c % 2 == 0)
                    {
                        sOut[(c / 2) - 1] |= (byte)(num & 0x0f);
                    }
                    else
                    {
                        sOut[c / 2] = (byte)(num << 4);
                    }

                    c++;
                }

                reverseByteArr(sOut);


                byte[] myP = new byte[4] { 0, 0, 0, 0 };
                //f = P(S1(B1)S2(B2)...S8(B8)) 
                calcP(sOut, myP);

                byte[] Lx = new byte[4];

                Lx = LArr[m - 1];

                for (int i = 0; i < Lx.Length; i++)
                {
                    myP[i] = (byte)(Lx[i] ^ myP[i]);
                }

                RArr.Add(myP);
                //Ln = Rn-1
                LArr.Add(RArr[m - 1]);
            }

            //Reverse order of last two blocks R16L16
            byte[] RLconcat = new byte[8];

            Array.Copy(RArr[RArr.Count - 1], RLconcat, RLconcat.Length / 2);
            Array.Copy(LArr[LArr.Count - 1], 0, RLconcat, 4, RLconcat.Length / 2);

            byte[] FinalBlocks = new byte[8];

            lastPerm(RLconcat, FinalBlocks);

            reverseByteArr(FinalBlocks);

            return FinalBlocks;
        }

        protected void printKeys()
        {
            byte tmpCnt = 1;
            foreach (var key in Keystates)
            {
                Console.Write("Key({0}): ", tmpCnt++);
                for (int j = 0; j < 4; j++)
                {
                    Console.Write("{0:X2}", key[j]);
                }
                Console.Write("\n");
            }
        }

        //Apply a final permutation IP-1
        protected void lastPerm(byte[] block, byte[] outP)
        {
            for (int i = 1, k = 0, j = 0; i <= IPneg.LongLength; i++)
            {
                if (k >= 8)
                {
                    j++;
                    k = 0;
                }
                if (j >= 8) break;

                int index = IPneg[j, k++];

                int bit = GetBit(block, index);

                SetBit(outP, i, bit);
            }
        }

        //The permutation P is defined in the following table. P yields a 32-bit output from a 32-bit input by permuting the bits of the input block.
        protected void calcP(byte[] inputS, byte[] outP)
        {
            for (int i = 1, k = 0, j = 0; i <= P.LongLength; i++)
            {
                if (k >= 4)
                {
                    j++;
                    k = 0;
                }
                if (j >= 8) break;

                int index = P[j, k++];

                int bit = GetBit(inputS, index);

                SetBit(outP, i, bit);
            }
        }

        protected void rotateKeyBitsLeft(byte[] key)
        {
            byte res = 0;
            byte tmp = 0;

            tmp = (byte)(key[0] & 1);
            key[0] = (byte)(key[0] >> 1);
            if (res == 1) key[0] |= 0x80;
            res = tmp;

            tmp = (byte)(key[3] & 1);
            key[3] = (byte)(key[3] >> 1);
            if (res == 1) key[3] |= 0x8;
            res = tmp;

            tmp = (byte)(key[2] & 1);
            key[2] = (byte)(key[2] >> 1);
            if (res == 1) key[2] |= 0x80;
            res = tmp;

            tmp = (byte)(key[1] & 1);
            key[1] = (byte)(key[1] >> 1);
            if (res == 1) key[1] |= 0x80;
            res = tmp;

            if (res == 1) key[0] |= 0x80;
        }

        protected void PrintStateBit(byte[] s, int len = 57, int sep = 8)
        {
            for (int i = 1; i < len; i++)
            {
                int bit = GetBit(s, i);
                Console.Write("{0}", bit);
                if (i % sep == 0)
                {
                    Console.Write(" ");
                }
            }
        }

        protected byte reverseInt8(byte value)
        {
            value = (byte)(((value & 0xF0) >> 4) | ((value & 0x0F) << 4));
            value = (byte)(((value & 0xCC) >> 2) | ((value & 0x33) << 2));
            value = (byte)(((value & 0xAA) >> 1) | ((value & 0x55) << 1));

            return value;
        }

        protected int GetBit(byte[] s, int n)
        {
            return (s[(n - 1) / 8] >> ((n - 1) % 8) & 1);
        }

        protected void SetBit(byte[] s, int n, int val)
        {
            s[(n - 1) / 8] = (byte)((s[(n - 1) / 8] & (byte)~(1 << ((n - 1) % 8))) | (val << ((n - 1) % 8)));
        }


    }
}
