using System.Security.Cryptography;
using System.Text;
class Passwords {
 public static string Hash(string password) {
  return System.BitConverter.ToString(MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(password)));
 }
}
