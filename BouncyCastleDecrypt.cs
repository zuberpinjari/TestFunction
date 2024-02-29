using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Microsoft.Azure.Storage;
using Microsoft.Azure.Storage.Blob;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.Linq;

namespace TestFunction
{
    public static class BouncyCastleDecrypt
    {
        [FunctionName("BouncyCastleDecrypt")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            try
            {
                string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
                FileNames data = JsonConvert.DeserializeObject<FileNames>(requestBody);

                string containerName = "teststuff";
                var passpharse = "abcd";

                CloudStorageAccount storageAccount = CloudStorageAccount.Parse(Environment.GetEnvironmentVariable("AzureWebJobsStorage"));
                CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();
                CloudBlobContainer container = blobClient.GetContainerReference(containerName);
                foreach (var file in data.FileName)
                {
                    CloudBlockBlob blob = container.GetBlockBlobReference(file);
                    CloudBlockBlob privateKey = container.GetBlockBlobReference("SECRET.asc");

                    using (MemoryStream inputBlobStream = new MemoryStream())
                    using (Stream privateKeyStream = new MemoryStream())
                    {
                        byte[] arrayFile = null;
                        await blob.DownloadToStreamAsync(inputBlobStream);
                        await privateKey.DownloadToStreamAsync(privateKeyStream);

                        var fileStream = DownloadAsFileStream(blob);
                        var encryptedData = DecryptStream(fileStream, privateKeyStream, passpharse);

                        // Create a new blob for the encrypted data
                        CloudBlockBlob encryptedBlob = container.GetBlockBlobReference(data.DestinationFolderName + "/decrypted_" + file.Split('/')[0]);

                        // Upload the encrypted data to the new blob
                        using (MemoryStream encryptedBlobStream = new MemoryStream(encryptedData))
                        {
                            await encryptedBlob.UploadFromStreamAsync(encryptedBlobStream);
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
        public static FileStream DownloadAsFileStream(CloudBlockBlob blob)
        {
            

            // Create a temporary file path
            string tempFilePath = Path.GetTempFileName();

            // Open a FileStream to write the downloaded content
            using (FileStream fileStream = new FileStream(tempFilePath, FileMode.Create, FileAccess.Write))
            {
                // Download the blob content as a Stream
                using (Stream blobStream = blob.OpenRead())
                {
                    // Copy the content of the blobStream to the FileStream
                    blobStream.CopyTo(fileStream);
                }
            }

            // Open the temporary file as a FileStream and return it
            return new FileStream(tempFilePath, FileMode.Open, FileAccess.Read);
        }
        public static byte[] DecryptStream(FileStream fileStream, Stream privateKeyStream, string privateKeyPassword)
        {
            try
            {
                // Read the private key from the stream
                PgpPrivateKey privateKey = ReadPrivateKey(privateKeyStream, privateKeyPassword);
                
                // Initialize a PgpObjectFactory to process the encrypted stream
                PgpObjectFactory pgpFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(fileStream));

                // Get the first object from the factory
                PgpObject pgpObject = pgpFactory.NextPgpObject();

                // If the object is a PgpEncryptedDataList, try to decrypt it
                if (pgpObject is PgpEncryptedDataList encryptedDataList)
                {
                    // Find the appropriate encrypted data packet
                    PgpPublicKeyEncryptedData encryptedData = null;
                    foreach (PgpPublicKeyEncryptedData data in encryptedDataList.GetEncryptedDataObjects())
                    {
                        if (privateKey.KeyId == data.KeyId)
                        {
                            encryptedData = data;
                            break;
                        }
                    }

                    if (encryptedData != null)
                    {
                        // Use the private key to decrypt the data
                        Stream decryptedStream = encryptedData.GetDataStream(privateKey);

                        // Read the decrypted data into a memory stream
                        MemoryStream decryptedOutput = new MemoryStream();
                        decryptedStream.CopyTo(decryptedOutput);

                        // Reset the position of the decrypted stream
                        decryptedOutput.Position = 0;

                        // Return the decrypted data as a byte array
                        return decryptedOutput.ToArray();
                    }
                }

                // If no encrypted data found or decryption fails, return null
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Decryption failed: {ex.Message}");
                return null;
            }
        }



        public static FileStream ConvertStreamToFileStream(Stream stream)
        {
            // Create a temporary file
            string tempFilePath = Path.GetTempFileName();

            // Create or overwrite the temporary file with the specified path
            using (FileStream fileStream = new FileStream(tempFilePath, FileMode.Create, FileAccess.Write))
            {
                // Set the position of the stream to the beginning
                stream.Position = 0;

                // Copy the content of the stream to the FileStream
                stream.CopyTo(fileStream);
            }

            // Reopen the temporary file as a FileStream
            return new FileStream(tempFilePath, FileMode.Open, FileAccess.ReadWrite);
        }
        public static PgpPrivateKey ReadPrivateKey(Stream privateKeyStream, string privateKeyPassword)
        {
            try
            {
                FileStream fileStream = ConvertStreamToFileStream(privateKeyStream);
                // Initialize a PgpKeyRingBundle with the provided private key stream
                PgpSecretKeyRingBundle secretKeyRingBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(fileStream));

                // Iterate through each secret key ring in the bundle
                foreach (PgpSecretKeyRing keyRing in secretKeyRingBundle.GetKeyRings())
                {
                    // Iterate through each secret key in the key ring
                    foreach (PgpSecretKey secretKey in keyRing.GetSecretKeys())
                    {
                        // Attempt to extract the private key using the provided password
                        PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(privateKeyPassword.ToCharArray());

                        // If the private key extraction is successful, return the private key
                        if (privateKey != null)
                        {
                            return privateKey;
                        }
                    }
                }

                // If no suitable private key is found, return null
                return null;
            }
            catch (PgpException ex)
            {
                Console.WriteLine($"Error reading private key: {ex.Message}");
                return null;
            }
        }

    }
}
