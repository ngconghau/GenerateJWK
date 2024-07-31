using Microsoft.IdentityModel.Tokens;

namespace GenerateJWKS.Enums
{
    public enum EcdsaAlgorithm
    {
        /// <summary>
        // No algorithm
        /// </summary>
        None,

        /// <summary>
        /// Signature algorithm ECDSA using P-256 and SHA-256
        /// </summary>
        [JsonWebAlgorithm(SecurityAlgorithms.EcdsaSha256, IsSignatureAlgorithm = true)]
        ES256,

        /// <summary>
        /// Signature algorithm ECDSA using P-384 and SHA-384
        /// </summary>
        [JsonWebAlgorithm(SecurityAlgorithms.EcdsaSha384, IsSignatureAlgorithm = true)]
        ES384,

        /// <summary>
        /// Signature algorithm ECDSA using P-521 and SHA-512
        /// </summary>
        [JsonWebAlgorithm(SecurityAlgorithms.EcdsaSha512, IsSignatureAlgorithm = true)]
        ES512,
        
        /// <summary>
        /// Encryption algorithm ECDH-ES using Concat KDF and CEK wrapped with "A128KW"
        /// </summary>
        [JsonWebAlgorithm(SecurityAlgorithms.EcdhEsA128kw, IsSignatureAlgorithm = false)]
        EcdhEsA128kw,
        
        /// <summary>
        /// Encryption algorithm ECDH-ES using Concat KDF and CEK wrapped with "A192KW"
        /// </summary>
        [JsonWebAlgorithm(SecurityAlgorithms.EcdhEsA192kw, IsSignatureAlgorithm = false)]
        EcdhEsA192kw,

        /// <summary>
        /// Encryption algorithm ECDH-ES using Concat KDF and CEK wrapped with "A256KW"
        /// </summary>
        [JsonWebAlgorithm(SecurityAlgorithms.EcdhEsA256kw, IsSignatureAlgorithm = false)]
        EcdhEsA256kw,
    }
}
