using EncryptedChatProject.Helpers;
using System.Text;

namespace EncryptedChatProject.Data
{
    public class SHA1Class
    {
        private static uint h0, h1, h2, h3, h4;

        public string CalculateSHA1(string input)
        {
            h0 = 0x67452301;
            h1 = 0xEFCDAB89;
            h2 = 0x98BADCFE;
            h3 = 0x10325476;
            h4 = 0xC3D2E1F0;

            byte[] data = Encoding.UTF8.GetBytes(input);
            ulong messageLength = (ulong)data.Length * 8;

            byte[] paddedData = new byte[data.Length + 1];
            Array.Copy(data, paddedData, data.Length);
            paddedData[data.Length] = 0x80;

            int paddingSize = (448 - (data.Length * 8 + 1) % 512 + 512) % 512 / 8;
            Array.Resize(ref paddedData, paddedData.Length + paddingSize + 8);

            byte[] lengthBytes = BitConverter.GetBytes(messageLength).Reverse().ToArray();
            Array.Copy(lengthBytes, 0, paddedData, paddedData.Length - 8, 8);

            int blockNum = paddedData.Length / 64;

            for (int i = 0; i < blockNum; i++)
            {
                byte[] block = new byte[64];
                Array.Copy(paddedData, i * 64, block, 0, 64);

                ProcessBlock(block);
            }

            Console.WriteLine(h0);
            Console.WriteLine(h1);
            Console.WriteLine(h2);
            Console.WriteLine(h3);
            Console.WriteLine(h4);

            byte[] hashBytes = BitConverter.GetBytes(h0).Concat(BitConverter.GetBytes(h1))
                                                     .Concat(BitConverter.GetBytes(h2))
                                                     .Concat(BitConverter.GetBytes(h3))
                                                     .Concat(BitConverter.GetBytes(h4))
                                                     .Reverse()
                                                     .ToArray();

            return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        }

        private static void ProcessBlock(byte[] block)
        {
            uint[] w = new uint[80];

            //prvih 16 elemenata je blok poruke
            for (int i = 0; i < 16; i++)
            {
                byte[] wordBytes = new byte[4];
                Array.Copy(block, i * 4, wordBytes, 0, 4);

                // Reverse the byte order if the system is little-endian
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(wordBytes);
                }

                w[i] = BitConverter.ToUInt32(wordBytes, 0);
            }


            for (int i = 16; i < 80; i++)
            {
                w[i] = BinaryHelper.ROL((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1);
            }

            uint a = h0, b = h1, c = h2, d = h3, e = h4;

            //runde
            for (int i = 0; i < 80; i++)
            {
                uint f, k, temp;

                if (i < 20)
                {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999;
                }
                else if (i < 40)
                {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                }
                else if (i < 60)
                {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                }
                else
                {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                temp = BinaryHelper.ROL(a, 5) + f + e + k + w[i];
                e = d;
                d = c;
                c = BinaryHelper.ROL(b, 30);
                b = a;
                a = temp;

                Console.WriteLine(a);
                Console.WriteLine(b);
                Console.WriteLine(c);
                Console.WriteLine(d);
                Console.WriteLine(e);
            }

            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;

        }
    }
}
