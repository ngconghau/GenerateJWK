using GenerateJWKS.Repositories.Interfaces;
using Jose;
using System.Security.Cryptography;
using System.Text;

namespace GenerateJWKS
{
    public class App
    {
        private readonly IJwkGenerator _jwkGenerator;

        private readonly string _cert = $"Certs";

        private readonly string _filePublicKeys = $"oidc-jwks-public.json";
        private readonly string _filePrivateKeys = $"oidc-jwks-private.json";

        private readonly string _filePrivateSigKeyPem = $"oidc-sig-private";
        private readonly string _filePrivateEncKeyPem = $"oidc-enc-private";
        public App(IJwkGenerator jwkGenerator)
        {
            _jwkGenerator = jwkGenerator;
        }

        public async Task RunAsync()
        {
            string kidSig = string.Empty;
            string kidEnc = string.Empty;

            while (string.IsNullOrEmpty(kidSig))
            {
                Console.Write("Please enter signature key id: ");
                kidSig = Console.ReadLine();
            }

            while (string.IsNullOrEmpty(kidEnc))
            {
                Console.Write("Please enter encrypt key id: ");
                kidEnc = Console.ReadLine();
            }

            await GenerateJwkSets(kidSig, kidEnc);
            Console.Write("Generate JWKS completed.");
            Console.ReadLine();

            await Task.CompletedTask;
        }

        private async Task GenerateJwkSets(string kidSig, string kidEnc)
        {
            try
            {
                var directory = Directory.GetCurrentDirectory();
                var certFolder = Path.Combine(directory, _cert);
                if (!Directory.Exists(certFolder))
                {
                    Directory.CreateDirectory(certFolder);
                }

                //generate key pairs
                var keySignature = _jwkGenerator.GenerateEcdsaKeyPairs(ECCurve.NamedCurves.nistP256, Enums.EcdsaAlgorithm.ES256, kidSig);
                var keyEncrypt = _jwkGenerator.GenerateEcdsaKeyPairs(ECCurve.NamedCurves.nistP256, Enums.EcdsaAlgorithm.EcdhEsA256kw, kidEnc);

                //create key set
                var listPrivateKeys = new List<Jose.Jwk>() { keySignature.Item1, keyEncrypt.Item1 };
                var privateKeySet = new Jose.JwkSet(listPrivateKeys);

                var listPublicKeys = new List<Jose.Jwk>() { keySignature.Item2, keyEncrypt.Item2 };
                var publicKeySet = new Jose.JwkSet(listPublicKeys);

                //write pem key to file
                byte[] privateKeySig = keySignature.Item3.ExportECPrivateKey();
                string privateKeySigPem = ConvertDERToPEM(privateKeySig, "EC PRIVATE KEY");

                byte[] privateKeyEnc = keyEncrypt.Item3.ExportECPrivateKey();
                string privateKeyEncPem = ConvertDERToPEM(privateKeyEnc, "EC PRIVATE KEY");

                var pathPrivateSigPem = $"{certFolder}/{_filePrivateSigKeyPem}";
                var pathPrivateEncPem = $"{certFolder}/{_filePrivateEncKeyPem}";

                await File.WriteAllTextAsync(pathPrivateSigPem, privateKeySigPem);
                await File.WriteAllTextAsync(pathPrivateEncPem, privateKeyEncPem);

                //write key set to file
                var pathPrivateCert = $"{certFolder}/{_filePrivateKeys}";
                var pathPublicCert = $"{certFolder}/{_filePublicKeys}";

                await WriteToFile(privateKeySet, pathPrivateCert);
                await WriteToFile(publicKeySet, pathPublicCert);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        private async static Task WriteToFile(JwkSet keySet, string pathCert)
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

        private static string ConvertDERToPEM(byte[] der, string pemLabel)
        {
            StringBuilder pemBuilder = new StringBuilder();
            pemBuilder.AppendLine($"-----BEGIN {pemLabel}-----");
            pemBuilder.AppendLine(Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks));
            pemBuilder.AppendLine($"-----END {pemLabel}-----");
            return pemBuilder.ToString();
        }
    }
}
