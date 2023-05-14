using System.Text;

namespace DesCipher
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string key   = String.Empty, 
                   input = String.Empty;

            Console.Write("Input key: ");
            key = Console.ReadLine();

            Console.Write("Input text: ");
            input = Console.ReadLine();

            byte[] inputBytes = Encoding.ASCII.GetBytes(input);
            byte[] keyBytes   = Encoding.ASCII.GetBytes(key);

            DES mydes = new DES(keyBytes);
            mydes.Init();


            Console.Write("\n[!] Key (hex): ");

            for (int i = 0; i < 8; i++)
            {
                if (i >= keyBytes.Length)
                    Console.Write("00");
                else 
                    Console.Write("{0:X2}", keyBytes[i]);
            }
            Console.Write("\n\n");

            /*List<byte[]> generatedKeys = mydes.GetKeys();

            for(int i =0;i < generatedKeys.Count;i++)
            {
                Console.Write("Key[{0}]: ", i + 1);
                foreach(var b in generatedKeys[i])
                {
                    Console.Write("{0:X2}", b);
                }
                Console.Write("\n");
            }*/

            byte[] cipher = mydes.Encrypt(inputBytes);

            Console.Write("\n[!] Cipher (hex): ");
            foreach(var b in cipher)
            {
                Console.Write("{0:X2}", b);
            }

            Console.Write("\n[!] Decrypted (text): ");

            string result = Encoding.ASCII.GetString(mydes.Decrypt(cipher));

            Console.Write("{0}\n", result);

            Console.ReadKey();
        }
    }
}