using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using System;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        string keyVaultUrl = "https://cfcstandard.vault.azure.net/";
        string secretName = "mySecret";
        string keyName = "CFCKey";

        // Replace with your UAMI Client ID
        string uamiClientId = "insights-test";

        // var credential = new ManagedIdentityCredential(clientId: uamiClientId);
        var credential = new DefaultAzureCredential(
                        new DefaultAzureCredentialOptions
                        {
                            ManagedIdentityClientId = uamiClientId
                        });

        // Read a secret
        var secretClient = new SecretClient(new Uri(keyVaultUrl), credential);
        var secret = await secretClient.GetSecretAsync(secretName);
        Console.WriteLine($"Secret value: {secret.Value}");

        // Read a key
        var keyClient = new KeyClient(new Uri(keyVaultUrl), credential);
        var key = await keyClient.GetKeyAsync(keyName);

        Console.WriteLine($"Secret value: {secret.Value.Value}");
        Console.WriteLine($"Key Id: {key.Value.Id}");
        Console.WriteLine($"Key name: {key.Value.Name}");
        Console.WriteLine($"Key operations: {key.Value.KeyOperations}");
        Console.WriteLine($"Key type: {key.Value.KeyType}");
        Console.WriteLine("\nDone.");


        // Optional: perform crypto operation (requires Key Vault Crypto User role)
        Console.WriteLine("\nEncrypting sample text using Key Vault key...");
        var cryptoClient = new CryptographyClient(key.Value.Id, credential);

        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("hello world");

        EncryptResult encryptResult = await cryptoClient.EncryptAsync(EncryptionAlgorithm.RsaOaep, plaintext);
        Console.WriteLine($"Encrypted bytes: {Convert.ToBase64String(encryptResult.Ciphertext)}");
    }

}

