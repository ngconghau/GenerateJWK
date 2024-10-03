using GenerateJWKS.Enums;
using System.Security.Cryptography;

namespace GenerateJWKS.Repositories.Interfaces
{
    public interface IJwkGenerator
    {
        Tuple<Jose.Jwk, Jose.Jwk, ECDsa> GenerateEcdsaKeyPairs(ECCurve eCCurve, EcdsaAlgorithm algorithm, string keyId);
    }
}
