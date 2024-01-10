namespace EncryptedChatProject.Helpers
{
    public class BinaryHelper
    {
        public static uint ROL(uint value, int positions)
        {
            positions %= 32;
            return (value << positions) | (value >> (32 - positions));
        }

        public static uint ROR(uint value, int positions)
        {
            positions %= 32;
            return (value >> positions) | (value << (32 - positions));
        }
                
        public static byte[] XOR(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }
            return result;
        }

        public static uint[] XOR(uint[] array1, uint[] array2)
        {
            if (array1.Length != array2.Length)
            {
                throw new ArgumentException("Arrays must have the same length for XOR operation.");
            }

            uint[] result = new uint[array1.Length];
            for (int i = 0; i < array1.Length; i++)
            {
                result[i] = array1[i] ^ array2[i];
            }

            return result;
        }

        public static byte[] HexStringToByteArray(string hexString)
        {
            int length = hexString.Length;
            byte[] byteArray = new byte[length / 2];

            for (int i = 0; i < length; i += 2)
            {
                byteArray[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            }

            return byteArray;
        }

        public static uint[] ByteArrayToUintArray(byte[] byteArray)
        {
            uint[] uintArray = new uint[byteArray.Length / 4];
            for (int i = 0; i < uintArray.Length; i++)
            {
                uintArray[i] = BitConverter.ToUInt32(byteArray, i * 4); //little-endian, revise
            }

            return uintArray;
        }

        public static string UintArrayToString(uint[] uintArray)
        {
            string text = "";
            byte[] byteArray = new byte[16];

            for(int i = 0; i<uintArray.Length; i += 4)
            {
                Array.Copy(BitConverter.GetBytes(uintArray[i]), 0, byteArray, i, 4);
            }

            text = System.Text.Encoding.UTF8.GetString(byteArray);

            return text;
        }
    }
}
