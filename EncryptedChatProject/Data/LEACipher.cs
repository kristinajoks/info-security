using EncryptedChatProject.Helpers;
using System.Security.Cryptography;
using System.Text;

namespace EncryptedChatProject.Data
{
    public class LEACipher : ICipherBehavior
    {
        private int keySize = 128;
        private int blockSize = 16; //128b, 16B;
        protected uint[,] roundKeys;
        private readonly uint[] delta = { unchecked((uint)0xc3efe9db), 0x44626b02, 0x79e27c8a, 0x78df30ec, 0x715ea49e, unchecked((uint)0xc785da0a), 
            unchecked((uint)0xe04ef22a), unchecked((uint)0xe5c40957) };
        private uint[] iv;

        public LEACipher(string key)
        {
            byte[] bytekey = BinaryHelper.HexStringToByteArray(key);
            this.keySize = bytekey.Length * 8;

            try
            {
                GenerateRoundKeys(bytekey);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
        
        
        public string Encrypt(string plaintext)
        {
            try
            {                
                byte[] paddedText = AddPKCS7Padding(plaintext);

                int blockCount = paddedText.Length / this.blockSize;
                uint[] plainUint = BinaryHelper.ByteArrayToUintArray(paddedText);

                uint[] ciphertext = new uint[plainUint.Length];

                iv = GenerateIV();
                                
                //0. element
                uint[] xorResult = new uint[4];

                uint[] currentBlock = new uint[4];

                Array.Copy(plainUint, 0, currentBlock, 0, 4);

                xorResult = BinaryHelper.XOR(currentBlock, iv);
                
                uint[] encryptedBlock = EncryptBlock(xorResult);
                Array.Copy(encryptedBlock, 0, ciphertext, 0, 4);

                //
                for(int i = 4; i < plainUint.Length - 4; i += 4)
                {
                    Array.Copy(plainUint, i, currentBlock, 0, 4);

                    uint[] previousCipher = new uint[4];
                    uint[] previousPlain = new uint[4];
                    Array.Copy(plainUint, i - 4, previousPlain, 0, 4);

                    uint[] xorResult1 = new uint[4];
                    Array.Copy(ciphertext, i - 4, previousCipher, 0, 4);

                    xorResult1 = BinaryHelper.XOR(previousCipher, previousPlain);

                    xorResult = BinaryHelper.XOR(currentBlock, xorResult1);

                    encryptedBlock = EncryptBlock(xorResult);

                    Array.Copy(encryptedBlock, 0, ciphertext, i, 4);
                }

                string cipherString = BinaryHelper.UintArrayToString(ciphertext);
               
                return cipherString;
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
                return plaintext;
            }
        }


        public uint[] EncryptBlock(uint[] plaintext) {

            int numOfRounds = keySize == 128 ? 24 : keySize == 192 ? 28 : 32;

            uint[,] X = new uint[numOfRounds + 1, plaintext.Length];
            uint[] cipherText = new uint[plaintext.Length];
            
            for (int i = 0; i < plaintext.Length; i++)
            {
                X[0,i] = plaintext[i];
            }

            for (int i = 0; i < numOfRounds; i++)
            {
                X[i + 1, 0] = BinaryHelper.ROL(X[i, 0] ^ this.roundKeys[i, 0] + X[i, 1] ^ this.roundKeys[i, 1], 9);
                X[i + 1, 1] = BinaryHelper.ROR(X[i, 1] ^ this.roundKeys[i, 2] + X[i, 2] ^ this.roundKeys[i, 3], 5);
                X[i + 1, 2] = BinaryHelper.ROR(X[i, 2] ^ this.roundKeys[i, 4] + X[i, 3] ^ this.roundKeys[i, 5], 3);
                X[i + 1, 3] = X[i, 0];
            }

            for (int i = 0; i < plaintext.Length; i++)
            {
                cipherText[i] = X[numOfRounds, i];
            }

            return cipherText; 
        }

        public string Decrypt(string ciphertext)
        {
            byte[] cipherByte = Encoding.UTF8.GetBytes(ciphertext);

            uint[] cipherUint = BinaryHelper.ByteArrayToUintArray(cipherByte);

            uint[] plaintext = new uint[cipherUint.Length];

            uint[] xorResult = new uint[4];

            uint[] currentBlock = new uint[4];

            //0. element
            Array.Copy(cipherUint, 0, currentBlock, 0, 4);

            uint[] decryptedBlock = DecryptBlock(currentBlock);

            xorResult = BinaryHelper.XOR(decryptedBlock, iv);

            Array.Copy(xorResult, 0, plaintext, 0, 4);

            //
            for (int i = 4; i < cipherUint.Length - 4; i += 4)
            {
                Array.Copy(cipherUint, i, currentBlock, 0, 4);
                decryptedBlock = DecryptBlock(currentBlock);

                uint[] previousPlain = new uint[4];
                Array.Copy(plaintext, i - 4, previousPlain, 0, 4);

                uint[] previousCipher = new uint[4];
                Array.Copy(cipherUint, i - 4, previousCipher, 0, 4);

                uint[] xorResult1 = new uint[4];
                xorResult1 = BinaryHelper.XOR(previousPlain, previousCipher);

                xorResult = BinaryHelper.XOR(xorResult1, decryptedBlock);

                Array.Copy(xorResult, 0, plaintext, i, 4);
            }

            string plainString = BinaryHelper.UintArrayToString(plaintext);

            return plainString;
        }

        public uint[] DecryptBlock(uint[] ciphertext) {

            int numOfRounds = keySize == 128 ? 24 : keySize == 192 ? 28 : 32;

            uint[,] X = new uint[numOfRounds + 1, ciphertext.Length];
            uint[] plainext = new uint[ciphertext.Length];


            for (int i = 0; i < ciphertext.Length; i++)
            {
                X[numOfRounds, i] = ciphertext[i];
            }


            for (int i = numOfRounds - 1; i >= 0; i--)
            {                
                X[i, 0] = X[i + 1, 3];
                X[i, 1] = (byte)(BinaryHelper.ROR(X[i + 1, 0], 9) - ((X[i, 0] ^ this.roundKeys[i, 0]) ^ this.roundKeys[i, 1]));
                X[i, 2] = (byte)(BinaryHelper.ROL(X[i + 1, 1], 5) - ((X[i, 1] ^ this.roundKeys[i, 2]) ^ this.roundKeys[i, 3]));
                X[i, 3] = (byte)(BinaryHelper.ROL(X[i + 1, 2], 3) - ((X[i, 2] ^ this.roundKeys[i, 4]) ^ this.roundKeys[i, 5]));
            }

            for (int i = 0; i < ciphertext.Length; i++)
            {
                plainext[i] = X[0, i];
            }

            return plainext; 
        }

        
        public byte[] AddPKCS7Padding(string input)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentException("Input string cannot be null or empty");
                    
            int paddingSize = this.blockSize - (input.Length % this.blockSize);
            if (paddingSize == 0)
                paddingSize = this.blockSize;

            string paddedInput = input + new string((char)paddingSize, paddingSize);
            return Encoding.UTF8.GetBytes(paddedInput);
        }

        public uint[] GenerateIV()
        {
            if (blockSize <= 0 || blockSize % 8 != 0)
            {
                throw new ArgumentException("Block size must be a positive multiple of 8.");
            }

            int ivSize = blockSize / 4;
            uint[] iv = new uint[ivSize];

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                byte[] randomBytes = new byte[ivSize * sizeof(uint)];
                rng.GetBytes(randomBytes);

                Buffer.BlockCopy(randomBytes, 0, iv, 0, randomBytes.Length);
            }

            return iv;
        }

        
        public void GenerateRoundKeys(byte[] keyByte)
        {
            if (this.keySize != 128 && this.keySize != 192 && this.keySize != 256)
                throw new ArgumentException("Invalid key size");

            int numOfRounds = this.keySize == 128 ? 24 : this.keySize == 192 ? 28 : 32;
            this.roundKeys = new uint[numOfRounds, 6]; //generise niz kljuceva od 192b

            uint[] key = BinaryHelper.ByteArrayToUintArray(keyByte);

            uint[] T = new uint[8];

            for (int i = 0; i < keyByte.Length / 4; i++)
            {
                T[i] = key[i];
            }
            
            if (this.keySize == 128)
            {
                for (int i = 0; i < numOfRounds; i++)
                {
                    T[0] = BinaryHelper.ROL(T[0] + BinaryHelper.ROL(this.delta[i % 4], i), 1);
                    T[1] = BinaryHelper.ROL(T[1] + BinaryHelper.ROL(this.delta[i % 4], i + 1), 3);
                    T[2] = BinaryHelper.ROL(T[2] + BinaryHelper.ROL(this.delta[i % 4], i + 2), 6);
                    T[3] = BinaryHelper.ROL(T[3] + BinaryHelper.ROL(this.delta[i % 4], i + 3), 11);

                    this.roundKeys[i, 0] = T[0];
                    this.roundKeys[i, 1] = T[1];
                    this.roundKeys[i, 2] = T[2];
                    this.roundKeys[i, 3] = T[1];
                    this.roundKeys[i, 4] = T[3];
                    this.roundKeys[i, 5] = T[1];
                }
            }
            else if(this.keySize == 192)
            {
                for (int i = 0; i < numOfRounds; i++)
                {
                    T[0] = BinaryHelper.ROL(T[0] + BinaryHelper.ROL(this.delta[i % 6], i), 1);
                    T[1] = BinaryHelper.ROL(T[1] + BinaryHelper.ROL(this.delta[i % 6], i + 1), 3);
                    T[2] = BinaryHelper.ROL(T[2] + BinaryHelper.ROL(this.delta[i % 6], i + 2), 6);
                    T[3] = BinaryHelper.ROL(T[3] + BinaryHelper.ROL(this.delta[i % 6], i + 3), 11);
                    T[4] = BinaryHelper.ROL(T[4] + BinaryHelper.ROL(this.delta[i % 6], i + 4), 13);
                    T[5] = BinaryHelper.ROL(T[5] + BinaryHelper.ROL(this.delta[i % 6], i + 5), 17);

                    this.roundKeys[i, 0] = T[0];
                    this.roundKeys[i, 1] = T[1];
                    this.roundKeys[i, 2] = T[2];
                    this.roundKeys[i, 3] = T[3];
                    this.roundKeys[i, 4] = T[4];
                    this.roundKeys[i, 5] = T[5];
                }
            }
            else
            {
                for (int i = 0; i < numOfRounds; i++)
                {
                    T[(6 * i) % 8] = BinaryHelper.ROL(T[(6 * i) % 8] + BinaryHelper.ROL(this.delta[i % 8], i), 1);
                    T[(6 * i + 1) % 8] = BinaryHelper.ROL(T[(6 * i + 1) % 8] + BinaryHelper.ROL(this.delta[i % 8], i + 1), 3);
                    T[(6 * i + 2) % 8] = BinaryHelper.ROL(T[(6 * i + 2) % 8] + BinaryHelper.ROL(this.delta[i % 8], i + 2), 6);
                    T[(6 * i + 3) % 8] = BinaryHelper.ROL(T[(6 * i + 3) % 8] + BinaryHelper.ROL(this.delta[i % 8], i + 3), 11);
                    T[(6 * i + 4) % 8] = BinaryHelper.ROL(T[(6 * i + 4) % 8] + BinaryHelper.ROL(this.delta[i % 8], i + 4), 13);
                    T[(6 * i + 5) % 8] = BinaryHelper.ROL(T[(6 * i + 5) % 8] + BinaryHelper.ROL(this.delta[i % 8], i + 5), 17);

                    this.roundKeys[i, 0] = T[(6 * i) % 8];
                    this.roundKeys[i, 1] = T[(6 * i + 1) % 8];
                    this.roundKeys[i, 2] = T[(6 * i + 2) % 8];
                    this.roundKeys[i, 3] = T[(6 * i + 3) % 8];
                    this.roundKeys[i, 4] = T[(6 * i + 4) % 8];
                    this.roundKeys[i, 5] = T[(6 * i + 5) % 8];
                }
            }
        }
                
    }
}
