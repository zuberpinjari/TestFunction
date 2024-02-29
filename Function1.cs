
using System.IO;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Microsoft.Azure.Storage.Blob;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.Storage;
using System;
using System.Linq;
using Microsoft.AspNetCore.Http;
using System.Web.Http;
using DidiSoft.Pgp;
using System.Linq;
using System.Collections.Generic;
using Newtonsoft.Json;
using Org.BouncyCastle.Utilities.IO;

public static class EncryptFileFunction
{
    [FunctionName("EncryptFileFunction_HttpTrigger")]
    public static async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Function,"post", Route = null)] HttpRequest req,
        ILogger log)
    {
        log.LogInformation("C# HTTP trigger function processed a request.");
        try
        {
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            FileNames data = JsonConvert.DeserializeObject<FileNames>(requestBody);

            string containerName = "teststuff";

            // Read the public key from a secret or configuration"-----BEGIN PGP PUBLIC KEY BLOCK----- Version: Keybase OpenPGP v1.0.0 Comment: https://keybase.io/crypto   xo0EZZRBAQEEAMEeEMwooqWny
            string publicKeyString = "-----BEGIN PGP PUBLIC KEY BLOCK----- Version: PGP Command Line v10.3.2 (Build 12260) (Win32) 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 DvxRSt+J0cY= =Nk4K -----END PGP PUBLIC KEY BLOCK-----";
            string privateKeyString = "-----BEGIN PGP PRIVATE KEY BLOCK----- Version: PGP Command Line v10.3.2 (Build 12260) (Win32) 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 jSKJYNwImP8I+pfAxULCx0sT+ecYRTlqAy0= =uBh5 -----END PGP PRIVATE KEY BLOCK-----";
            string passphrase = "adfP0c";

            // Retrieve blob from Azure Storage
            // Retrieve blob from Azure Storage
            CloudStorageAccount storageAccount = CloudStorageAccount.Parse(Environment.GetEnvironmentVariable("AzureWebJobsStorage"));
            CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();
            CloudBlobContainer container = blobClient.GetContainerReference(containerName);
            foreach (var file in data.FileName)
            {
                CloudBlockBlob blob = container.GetBlockBlobReference(file);

                using (MemoryStream inputBlobStream = new MemoryStream())
                {
                    await blob.DownloadToStreamAsync(inputBlobStream);

                    // Your PGP encryption logic here
                    var encryptedData = EncryptDataAndSign(inputBlobStream, publicKeyString, privateKeyString, passphrase);

                    //var encryptedData = EncryptDataandSign(inputBlobStream, publicKeyString, privateKeyString, passphrase);
                    //byte[] encryptedData = EncryptData(inputBlobStream, publicKeyString);

                    // Create a new blob for the encrypted data
                    CloudBlockBlob encryptedBlob = container.GetBlockBlobReference(data.DestinationFolderName + "/encrypted_" + file.Split('/')[0]);

                    // Upload the encrypted data to the new blob
                    using (MemoryStream encryptedBlobStream = new MemoryStream(encryptedData))
                    {
                        await encryptedBlob.UploadFromStreamAsync(encryptedBlobStream);
                    }

                    log.LogInformation($"Encryption completed for {file}");

                }
            }
            return new OkObjectResult($"Encryption completed!");

        }
        catch (Exception ex)
        {
            log.LogError("Something went wrong: {0}", ex.Message);
            return new BadRequestObjectResult(ex.Message);
        }
    }

    private static byte[] EncryptData(Stream dataStream, string publicKeyString)
    {
        // Initialize the encryption engine
        PGPLib pgp = new PGPLib();

        // Set the output stream (where the encrypted data will be written)
        using (MemoryStream encryptedDataStream = new MemoryStream())
        {
            // Convert the public key string to a Stream
            using (Stream publicKeyStream = new MemoryStream(Encoding.UTF8.GetBytes(publicKeyString)))
            {
                // Encrypt the data using the public key stream
                pgp.EncryptStream(dataStream, publicKeyStream, encryptedDataStream, true, true);
            }

            // Return the encrypted data as a byte array
            return encryptedDataStream.ToArray();
        }
    }

    [FunctionName("DecryptFileFunction_HttpTrigger")]
    public static async Task<IActionResult> DecryptRun(
    [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
    ILogger log)
    {
        log.LogInformation("C# HTTP trigger function processed a request.");
        try
        {
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            FileNames data = JsonConvert.DeserializeObject<FileNames>(requestBody);

            string containerName = "adfpluspoc";

            // Read the private key and passphrase from a secret or configuration
            string privateKeyString = "-----BEGIN PGP PRIVATE KEY BLOCK----- Version: Keybase OpenPGP v1.0.0 Comment: https://keybase.io/crypto   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 =Ib1e -----END PGP PRIVATE KEY BLOCK-----";
            string passphrase = "ADFpluspoc";

            // Retrieve blob from Azure Storage
            CloudStorageAccount storageAccount = CloudStorageAccount.Parse(Environment.GetEnvironmentVariable("AzureWebJobsStorage"));
            CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();
            CloudBlobContainer container = blobClient.GetContainerReference(containerName);

            foreach (var file in data.FileName)
            {
                CloudBlockBlob blob = container.GetBlockBlobReference(file);

                using (MemoryStream inputBlobStream = new MemoryStream())
                {
                    await blob.DownloadToStreamAsync(inputBlobStream);

                    // Your PGP decryption logic here
                    byte[] decryptedData = DecryptData(inputBlobStream, privateKeyString, passphrase);

                    // Create a new blob for the decrypted data
                    CloudBlockBlob decryptedBlob = container.GetBlockBlobReference(data.DestinationFolderName + "/decrypted_"+ file.Split('/')[1]);

                    // Upload the decrypted data to the new blob
                    using (MemoryStream decryptedBlobStream = new MemoryStream(decryptedData))
                    {
                        await decryptedBlob.UploadFromStreamAsync(decryptedBlobStream);
                    }

                    log.LogInformation($"Decryption completed for {file}");
                }
            }
            return new OkObjectResult($"Decryption completed!");
        }
        catch (Exception ex)
        {
            log.LogError("Something went wrong: {0}", ex.Message);
            return new BadRequestObjectResult(ex.Message);
        }
    }

    private static byte[] DecryptData(Stream encryptedDataStream, string privateKeyString, string passphrase)
    {
        // Initialize the decryption engine
        PGPLib pgp = new PGPLib();

        // Set the output stream (where the decrypted data will be written)
        using (MemoryStream decryptedDataStream = new MemoryStream())
        {
            // Convert the private key string to a Stream
            using (Stream privateKeyStream = new MemoryStream(Encoding.UTF8.GetBytes(privateKeyString)))
            {
                // Decrypt the data using the private key stream
                pgp.DecryptStream(encryptedDataStream, privateKeyStream, passphrase, decryptedDataStream);
            }

            // Return the decrypted data as a byte array
            return decryptedDataStream.ToArray();
        }
    }

    private static byte[] EncryptDataandSign(Stream dataStream, string publicKeyString, string privateKeyString, string privateKeyPassword)
    {
        // Initialize the encryption engine
        PGPLib pgp = new PGPLib();
        MemoryStream encryptedOutput = new MemoryStream();
        // Set the output stream (where the encrypted data will be written)
        using (MemoryStream encryptedDataStream = new MemoryStream())
        {
            // Convert the public key and private key strings to streams

            using (Stream publicKeyStream = new MemoryStream(Encoding.UTF8.GetBytes(publicKeyString)))
            using (Stream privateKeyStream = new MemoryStream(Encoding.UTF8.GetBytes(privateKeyString)))
            {
                // Sign and encrypt the data
                pgp.SignAndEncryptStream(dataStream, "Myfile.txt", privateKeyStream, privateKeyPassword, publicKeyStream, encryptedOutput, true, true);

                // Reset the encrypted data stream position for reading
                encryptedOutput.Seek(0, SeekOrigin.Begin);

                // Read the encrypted and signed data into a byte array
                byte[] encryptedAndSignedData = new byte[encryptedOutput.Length];
                encryptedOutput.Read(encryptedAndSignedData, 0, encryptedAndSignedData.Length);

                // Return the encrypted and signed data as a byte array
                return encryptedAndSignedData;
            }
        }
    }
    public static byte[] EncryptDataAndSign(Stream dataStream, string publicKeyString, string privateKeyString, string privateKeyPassword)
    {
        var publicKey = ReadPublicKey("C:\\Users\\xpinjajub\\Documents\\publickKey.asc");
        //PgpPublicKey publicKey = ReadPublicKey(publicKeyString);
        PgpPrivateKey privateKey = ReadPrivateKey(privateKeyString, privateKeyPassword);

        // Initialize signature generator
        PgpSignatureGenerator signatureGenerator = new PgpSignatureGenerator(publicKey.Algorithm, HashAlgorithmTag.Sha256);
        signatureGenerator.InitSign(PgpSignature.BinaryDocument, privateKey);

        // Create encrypted output stream
        MemoryStream encryptedOutput = new MemoryStream();
        using (Stream encryptedDataStream = encryptedOutput)
        {
            // Create compressed data generator
            PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
            using (Stream compressedStream = compressedDataGenerator.Open(encryptedDataStream))
            {
                // Create literal data generator
                PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();
                using (Stream literalDataStream = literalDataGenerator.Open(compressedStream, PgpLiteralData.Binary, "MyFile.txt", DateTime.UtcNow, new byte[4096]))
                {
                    // Sign and encrypt the data
                    signatureGenerator.GenerateOnePassVersion(false).Encode(literalDataStream);
                    dataStream.CopyTo(literalDataStream);
                }
            }
        }

        // Close the signature generator
        signatureGenerator.Generate().Encode(encryptedOutput);

        return encryptedOutput.ToArray();
    }

    private static PgpPublicKey ReadPublicKey(string publicKeyFile)
    {
        
            using (Stream inputStream = File.OpenRead(publicKeyFile))
            {
            try
            {
                PgpPublicKeyRingBundle publicKeyRingBundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(inputStream));
                var publickey = publicKeyRingBundle.GetKeyRings();
                foreach (PgpPublicKeyRing keyRing in publicKeyRingBundle.GetKeyRings())
                {
                    foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                    {
                        if (key.IsEncryptionKey)
                        {
                            return key;
                        }
                    }
                }
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }
        
    }
    public static PgpPublicKey GetPgpPubKey(string publicKeyFilePath)
    {
        using (Stream keyFileStream = File.OpenRead(publicKeyFilePath))
        using (ArmoredInputStream armoredInputStream = new(keyFileStream))
        {
            try
            {
                // Read the contents of the ArmoredInputStream into a byte array
                byte[] keyData = Streams.ReadAll(armoredInputStream);

                // Create a new stream from the byte array
                using Stream keyDataStream = new MemoryStream(keyData);
                PgpPublicKeyRingBundle publicKeyRingBundle = new(keyDataStream);

                // Assuming you want the first public key in the file
                PgpPublicKeyRing publicKeyRing = publicKeyRingBundle.GetKeyRings().OfType<PgpPublicKeyRing>().FirstOrDefault();

                if (publicKeyRing != null)
                {
                    return publicKeyRing.GetPublicKeys().OfType<PgpPublicKey>().FirstOrDefault();
                }
                else
                {
                    throw new InvalidOperationException("No public key ring found in the specified key file.");
                }
            }
            catch (PgpException ex)
            {
                Console.WriteLine($"Error reading the key file: {ex.Message}");
                throw;
            }
            catch (IOException ex)
            {
                Console.WriteLine($"IO error reading the key file: {ex.Message}");
                throw;
            }
        }
    }
    

    public static PgpPrivateKey ReadPrivateKey(string privateKeyString, string privateKeyPassword)
    {
        using (Stream inputStream = PgpUtilities.GetDecoderStream(new MemoryStream(Encoding.UTF8.GetBytes(privateKeyString))))
        {
            PgpSecretKeyRingBundle secretKeyRingBundle = new PgpSecretKeyRingBundle(inputStream);
            PgpSecretKey secretKey = secretKeyRingBundle.GetSecretKey(0);
            return secretKey.ExtractPrivateKey(privateKeyPassword.ToCharArray());
        }
    }



}


public class FileNames
{
    public string DestinationFolderName { get; set; }
    public List<string> FileName { get; set; }
}
