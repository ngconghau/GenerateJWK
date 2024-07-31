using GenerateJWKS.Repositories.Interfaces;
using Jose;
using System.Security.Cryptography;

namespace GenerateJWKS
{
    public class App
    {
        private readonly IJwkGenerator _jwkGenerator;

        private readonly string _certFolder = $"Certs";

        private readonly string _filePublicKeys = $"oidc-spcp-public.json";
        private readonly string _filePrivateKeys = $"oidc-spcp-secret.json";
        public App(IJwkGenerator jwkGenerator)
        {
            _jwkGenerator = jwkGenerator;
        }

        public async Task RunAsync()
        {

            await GenerateJwkSets();
            await Task.CompletedTask;
        }

        private async Task GenerateJwkSets()
        {
            try
            {
                //generate key pairs
                var keySignature = _jwkGenerator.GenerateEcdsaKeyPairs(ECCurve.NamedCurves.nistP256, Enums.EcdsaAlgorithm.ES256, "oidc-sig-pub");
                var keyEncrypt = _jwkGenerator.GenerateEcdsaKeyPairs(ECCurve.NamedCurves.nistP256, Enums.EcdsaAlgorithm.EcdhEsA128kw, "oidc-enc-pub");

                //create key set
                var listPrivateKeys = new List<Jose.Jwk>() { keySignature.Item1, keyEncrypt.Item1 };
                var privateKeySet = new Jose.JwkSet(listPrivateKeys);

                var listPublicKeys = new List<Jose.Jwk>() { keySignature.Item2, keyEncrypt.Item2 };
                var publicKeySet = new Jose.JwkSet(listPublicKeys);

                //write key set to file
                var pathPrivateCert = $"{_certFolder}/{_filePrivateKeys}";
                var pathPublicCert = $"{_certFolder}/{_filePublicKeys}";
                await WriteToFile(privateKeySet, pathPrivateCert);
                await WriteToFile(publicKeySet, pathPublicCert);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        private async Task WriteToFile(JwkSet keySet, string pathCert)
        {
            using (FileStream fileStream = new(pathCert, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
            {
                using (StreamWriter writer = new StreamWriter(fileStream))
                {
                    fileStream.SetLength(0);
                    var keys = keySet.ToJson();
                    await writer.WriteLineAsync(keys);
                }
            }
        }
    }
}
