using GenerateJWKS.Enums;
using GenerateJWKS.Repositories.Interfaces;
using System.Security.Cryptography;

namespace GenerateJWKS.Repositories
{
    public class JwkGenerator : IJwkGenerator
    {
        public Tuple<Jose.Jwk, Jose.Jwk, ECDsa> GenerateEcdsaKeyPairs(ECCurve eCCurve, EcdsaAlgorithm algorithm, string keyId)
        {
            var eCDsa = ECDsa.Create(eCCurve);
            var privateKey = GenerateKey(eCDsa, algorithm , keyId);
            var publicKey = GenerateKey(eCDsa, algorithm , keyId, false);

            return Tuple.Create(privateKey, publicKey, eCDsa);
        }

        private Jose.Jwk GenerateKey(ECDsa eCDsa, EcdsaAlgorithm algorithm, string keyId, bool includePrivateKey = true)
        {
            var algorithmInfo = algorithm.GetJsonWebAlgorithm();
            var result = new Jose.Jwk(eCDsa, includePrivateKey);

            result.Use = algorithmInfo?.PublicKeyUse;
            result.Alg = algorithmInfo?.Name;
            result.KeyId = string.IsNullOrWhiteSpace(keyId) ? Guid.NewGuid().ToString() : keyId;

            return result;
        }
    }
}
