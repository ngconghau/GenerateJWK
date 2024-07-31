using GenerateJWKS.Enums;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace GenerateJWKS.Extensions
{
    public static class JwkSecurityKeyExtensions
    {
        /// <summary>
        /// Gets the JsonWebKey representation of the ECDSA key.
        /// </summary>
        /// <param name="key">The ECDSA security key.</param>
        /// <param name="algorithm">The algorithm for which this key will be used.</param>
        /// <param name="includePrivateKey">Include private key in JsonWebKey (if the current key contains the private key).</param>
        /// <returns>The JsonWebKey representation of the ECDSA key.</returns>
        public static JsonWebKey ToJwkExtensions(this ECDsaSecurityKey key, EcdsaAlgorithm algorithm, bool includePrivateKey = true)
        {
            var algorithmInfo = algorithm.GetJsonWebAlgorithm();
            JsonWebKey result = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);

            result.Use = algorithmInfo?.PublicKeyUse;
            result.Alg = algorithmInfo?.Name;

            if (!includePrivateKey)
            {
                result.D = null;
            }

            return result;
        }

        /// <summary>
        /// Gets the JsonWebKey representation of the RSA key
        /// </summary>
        /// <param name="includePrivateKey">Include private key in JsonWebKey (if the current key contains the private key)</param>
        /// <param name="algorithm">Signature or Encryption algorithm for which this key will be used for</param>
        /// <returns></returns>
        public static JsonWebKey ToJwk(this RsaSecurityKey key, RsaAlgorithm algorithm, bool includePrivateKey = true)
        {
            RSAParameters parameters;

            if (key.Rsa != null)
                parameters = key.Rsa.ExportParameters(includePrivateKey);
            else
                parameters = key.Parameters;

            var algorithmInfo = algorithm.GetJsonWebAlgorithm();
            JsonWebKey result = new JsonWebKey()
            {
                Kty = JsonWebAlgorithmsKeyTypes.RSA,
                Kid = key.KeyId,
                Use = algorithmInfo?.PublicKeyUse,
                Alg = algorithmInfo?.Name,
                N = parameters.Modulus == null ? null : Base64UrlEncoder.Encode(parameters.Modulus),
                E = parameters.Exponent == null ? null : Base64UrlEncoder.Encode(parameters.Exponent)
            };

            if (includePrivateKey)
            {
                result.P = parameters.P == null ? null : Base64UrlEncoder.Encode(parameters.P);
                result.Q = parameters.Q == null ? null : Base64UrlEncoder.Encode(parameters.Q);
                result.D = parameters.D == null ? null : Base64UrlEncoder.Encode(parameters.D);
                result.DQ = parameters.DQ == null ? null : Base64UrlEncoder.Encode(parameters.DQ);
                result.DP = parameters.DP == null ? null : Base64UrlEncoder.Encode(parameters.DP);
                result.QI = parameters.InverseQ == null ? null : Base64UrlEncoder.Encode(parameters.InverseQ);
            }
            return result;
        }

    }
}
