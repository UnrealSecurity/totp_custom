using System.Text;
using System.Security.Cryptography;

class Authenticator
{
    private static char[] digits = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
    private static byte[] magic = new byte[] { 0x41, 0x55, 0x54, 0x48 };
    private List<Hash> hashes = new List<Hash>();

    private const string err_secretMustNotBeNull = "Secret must not be null.";

    public byte[]? Secret;
    public int Length = 6;
    public int Expire = 30;

    /// <summary>
    /// Create new Authenticator
    /// </summary>
    public Authenticator() { }

    /// <summary>
    /// Create new Authenticator
    /// </summary>
    /// <param name="secret">Secret key</param>
    public Authenticator(byte[] secret)
    {
        this.Secret = secret;
    }

    /// <summary>
    /// Create new Authenticator
    /// </summary>
    /// <param name="length">Passcode length</param>
    /// <param name="expire">Passcode expiration time in seconds</param>
    public Authenticator(int length, int expire)
    {
        this.Length = length;
        this.Expire = expire;
    }

    /// <summary>
    /// Create new Authenticator
    /// </summary>
    /// <param name="secret">Secret key</param>
    /// <param name="length">Passcode length</param>
    public Authenticator(byte[] secret, int length)
    {
        this.Secret = secret;
        this.Length = length;
    }

    /// <summary>
    /// Create new Authenticator
    /// </summary>
    /// <param name="secret">Secret key</param>
    /// <param name="length">Passcode length</param>
    /// <param name="expire">Passcode expiration time in seconds</param>
    public Authenticator(byte[] secret, int length, int expire)
    {
        this.Secret = secret;
        this.Length = length;
        this.Expire = expire;
    }

    public struct Details
    {
        public string Name = "";
        public string Description = "";
    }

    private struct Hash
    {
        public int Value;
        public long Time;
    }

    private string GetCode(long timestamp)
    {
        if (Secret == null) throw new Exception(err_secretMustNotBeNull);

        /**
         * Convert timestamp to byte array
         */
        var timestamp_bytes = BitConverter.GetBytes(timestamp);

        /**
         * Create new HMAC SHA-256 instance using the secret key
         */
        using (var hmacsha256 = new HMACSHA256(Secret))
        {
            /**
             * Compute HMAC SHA-256 hash from timestamp bytes
             */
            byte[] hash_bytes = hmacsha256.ComputeHash(timestamp_bytes);

            /**
             * Get the first 4 bytes from hash bytes 
             * and convert it to 32-bit integer
             */
            int hash_value = BitConverter.ToInt32(hash_bytes, 0);

            /**
             * Initialize new random generator using 
             * the hash_value as the seed
             */
            var random = new Random(hash_value);

            /**
             * Generate the password
             */
            string password = String.Empty;

            for (int i = 0; i < Length; i++)
            {
                password += digits[random.Next(0, digits.Length - 1)];
            }

            return password;
        }
    }

    /// <summary>
    /// Clear hash value cache
    /// </summary>
    public void Clear()
    {
        hashes.Clear();
    }

    /// <summary>
    /// Get one time passcode that will be valid for {expire} seconds
    /// </summary>
    public string GetCode()
    {
        return GetCode(DateTimeOffset.Now.ToUnixTimeSeconds());
    }

    /// <summary>
    /// Verify one time passcode
    /// </summary>
    /// <param name="code">Passcode to verify</param>
    public bool Verify(string code)
    {
        if (code.Length != Length) return false;

        long timestamp = DateTimeOffset.Now.ToUnixTimeSeconds();

        /**
         * Remove expired hash values 
         * & check if code is already used
         */
        int hashCode = code.GetHashCode();
        bool used = false;

        for (int i=0; i < hashes.Count; i++)
        {
            if (timestamp - hashes[i].Time > Expire)
            {
                hashes.RemoveAt(i);
                i--;
            }
            else if (hashes[i].Value == hashCode)
            {
                used = true;
            }
        }

        if (used) return false;

        /**
         * Check if code is valid
         */
        for (long value = timestamp - Expire; value < timestamp; value++)
        {
            if (GetCode(value) == code)
            {
                hashes.Add(new Hash
                {
                    Value = hashCode,
                    Time = DateTimeOffset.Now.ToUnixTimeSeconds()
                });

                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Export application details and secret key in binary format
    /// </summary>
    /// <param name="details">Details to include with the secret key</param>
    public byte[] Export(Details details)
    {
        if (Secret == null) throw new Exception(err_secretMustNotBeNull);

        using (var stream = new MemoryStream())
        {
            using (var writer = new BinaryWriter(stream))
            {
                /**
                 * Write magic bytes
                 */
                writer.Write(magic);

                /**
                 * Write name prefixed with it's length
                 */
                writer.Write(details.Name.Length);
                writer.Write(Encoding.UTF8.GetBytes(details.Name));

                /**
                 * Write description prefixed with it's length
                 */
                writer.Write(details.Description.Length);
                writer.Write(Encoding.UTF8.GetBytes(details.Description));

                /**
                 * Write the secret key bytes
                 */
                writer.Write(Secret.Length);
                writer.Write(Secret);

                return stream.ToArray();
            }
        }
    }

    /// <summary>
    /// Import secret key from raw binary format
    /// </summary>
    /// <param name="array">Application details & secret key in binary format</param>
    public bool Import(byte[] array, out Details details)
    {
        details = new Details();

        using (var stream = new MemoryStream(array))
        {
            using (var reader = new BinaryReader(stream))
            {
                byte[] magic = reader.ReadBytes(Authenticator.magic.Length);

                if (magic.SequenceEqual(Authenticator.magic))
                {
                    details.Name = Encoding.UTF8.GetString(reader.ReadBytes(reader.ReadInt32()));
                    details.Description = Encoding.UTF8.GetString(reader.ReadBytes(reader.ReadInt32()));
                    this.Secret = reader.ReadBytes(reader.ReadInt32());

                    return true;
                }
            }
        }

        return false;
    }
}