using System.Security.Cryptography;
using System.Text;

namespace TruKare.Reports.Services;

public class Sha256HashService : IHashService
{
    public string ComputeHash(string path)
    {
        using var stream = File.OpenRead(path);
        using var sha = SHA256.Create();
        var bytes = sha.ComputeHash(stream);
        return Convert.ToHexString(bytes);
    }
}
