namespace EncryptedChatProject.Data
{
    public class CipherContext
    {
        private ICipherBehavior _cipherBehavior;

        public CipherContext() { }

        public  CipherContext(ICipherBehavior cipherBehavior)
        {
            _cipherBehavior = cipherBehavior;
        }

        public void SetCipherBehavior(ICipherBehavior cipherBehavior)
        {
            _cipherBehavior = cipherBehavior;
        }

        public string Encrypt(string plaintext)
        {
            return _cipherBehavior.Encrypt(plaintext);
        }

        public string Decrypt(string ciphertext)
        {
            return _cipherBehavior.Decrypt(ciphertext);
        }
    }
}
