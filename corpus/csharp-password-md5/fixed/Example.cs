using System.Security.Cryptography;
class Passwords {
 public static string Hash(string password, byte[] uniqueSalt) {
  return System.Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(password, uniqueSalt, 600000, HashAlgorithmName.SHA256, 32));
 }
}
