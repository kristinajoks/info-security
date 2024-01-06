namespace EncryptedChatProject.Data
{
    public interface ICipherBehavior
    {
        public string Encrypt(string plaintext)
        {
            return plaintext;
        }

        public string Decrypt(string ciphertext)
        {
            return ciphertext;
        }

    }
}
