using System.Text;

namespace EncryptedChatProject.Data
{
    public class FoursquareCipher : ICipherBehavior
    {
        private readonly char[,] orderedAlphabet;
        private readonly char[,] keySquare1;
        private readonly char[,] keySquare2;
        private bool keysAvailable = false;

        public FoursquareCipher(string key1, string key2)
        {
            orderedAlphabet = GenerateAlphabetMatrix();
            if (key1 != null && key1 != "" &&
                key2 != null && key2 != "")
            {
                keysAvailable = true;
                keySquare1 = GenerateKeySquare(key1);
                keySquare2 = GenerateKeySquare(key2);
            }
        }

        private char[,] GenerateAlphabetMatrix()
        {
            char[,] matrix = new char[5, 5];
            char currentChar = 'A';

            for (int row = 0; row < 5; row++)
            {
                for (int col = 0; col < 5; col++)
                {
                    if (currentChar == 'J')
                    {
                        currentChar++;
                    }

                    matrix[row, col] = currentChar++;
                }
            }

            return matrix;
        }

        private char[,] GenerateKeySquare(string key)
        {
            char[,] keySquare = new char[5, 5];
            int index = 0;

            for (int row = 0; row < 5; row++)
            {
                for (int col = 0; col < 5; col++)
                {
                    keySquare[row, col] = key[index++];
                }
            }

            return keySquare;
        }

        private Tuple<int, int> FindChar(char[,] keySquare, char ch)
        {
            for (int row = 0; row < 5; row++)
            {
                for (int col = 0; col < 5; col++)
                {
                    if (keySquare[row, col] == ch)
                    {
                        return Tuple.Create(row, col);
                    }
                }
            }

            return null;
        }

        public string Encrypt(string plaintext)
        {
            if(!keysAvailable)
                return plaintext;

            plaintext = plaintext.ToUpper().Replace("J", "I");
            plaintext = string.Join("", plaintext.Split(default(string[]), StringSplitOptions.RemoveEmptyEntries));

            StringBuilder ciphertext = new StringBuilder();

            for (int i = 0; i < plaintext.Length; i += 2)
            {
                char ch1 = plaintext[i];
                char ch2 = (i + 1 < plaintext.Length) ? plaintext[i + 1] : 'X';

                Tuple<int, int> position1 = FindChar(orderedAlphabet, ch1);
                Tuple<int, int> position2 = FindChar(orderedAlphabet, ch2);

                int row1 = 0, col1 = 0, row2 = 0, col2 = 0;

                if (position1 != null && position2 != null)
                {
                    row1 = position1.Item1;
                    col1 = position1.Item2;

                    row2 = position2.Item1;
                    col2 = position2.Item2;

                    char encryptedCh1 = keySquare1[row1, col2];
                    char encryptedCh2 = keySquare2[row2, col1];

                    ciphertext.Append(encryptedCh1);
                    ciphertext.Append(encryptedCh2);
                }
            }


            return ciphertext.ToString();
        }

        public string Decrypt(string ciphertext)
        {
            if(!keysAvailable)
                return ciphertext;

            StringBuilder plaintext = new StringBuilder();
           
            for (int i = 0; i < ciphertext.Length; i += 2)
            {
                char ch1 = ciphertext[i];
                char ch2 = (i + 1 < ciphertext.Length) ? ciphertext[i + 1] : 'X';

                Tuple<int, int> position1 = FindChar(keySquare1, ch1);
                Tuple<int, int> position2 = FindChar(keySquare2, ch2);

                if (position1 != null && position2 != null)
                {
                    int row1 = position1.Item1;
                    int col1 = position1.Item2;
                    int row2 = position2.Item1;
                    int col2 = position2.Item2;

                    char decryptedCh1 = orderedAlphabet[row1, col2];
                    char decryptedCh2 = orderedAlphabet[row2, col1];

                    plaintext.Append(decryptedCh1);
                    plaintext.Append(decryptedCh2);
                                    
                }
                
            }

            return plaintext.ToString();
        }
    }

}
