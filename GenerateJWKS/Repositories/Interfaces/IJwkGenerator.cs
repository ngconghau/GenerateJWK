using GenerateJWKS.Enums;
using System.Security.Cryptography;

namespace GenerateJWKS.Repositories.Interfaces
{
    public interface IJwkGenerator
    {
        Tuple<Jose.Jwk, Jose.Jwk> GenerateEcdsaKeyPairs(ECCurve eCCurve, EcdsaAlgorithm algorithm, string keyId);
    }
}
