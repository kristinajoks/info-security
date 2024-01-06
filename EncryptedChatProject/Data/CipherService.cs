namespace EncryptedChatProject.Data
{
    public class CipherService
    {
        public event Action OnAlgorithmChanged;

        public void ChangeAlgorithm()
        {
            OnAlgorithmChanged?.Invoke();
        }
    }
}
