namespace TOTP_Custom
{
    public class Program
    {
        static void Main(string[] args)
        {
            /**
             * Create new Authenticator instance and import 
             * previously exported secret
             */
            var auth = new Authenticator();

            if (auth.Import(
                Convert.FromBase64String("QVVUSB5VbnJlYWwgU2VjdXJpdHkgKEhlYXBPdmVycmlkZSkAIAAAAF/U0Edq8hlBduY45dr8cnm/9y0Xxb5srBU5DlPM98Sw"), 
                out Authenticator.Details details))
            {
                Console.WriteLine($"Import successful ({details.Name})");
            }
            else
            {
                Console.WriteLine($"Import failed");
            }

            /**
             * Print time based passcode that is valid for 30 seconds
             */
            Console.WriteLine($"Your code: {auth.GetCode()}");

            /**
             * Loop verify authentication code
             */
            while (true)
            {
                Console.Write("Enter code: ");
                string? code = Console.ReadLine();

                if (code != null && auth.Verify(code.Replace(" ", "")))
                {
                    Console.WriteLine($"Code is valid");
                }
                else
                {
                    Console.WriteLine($"Code is invalid");
                }
            }
        }
    }
}