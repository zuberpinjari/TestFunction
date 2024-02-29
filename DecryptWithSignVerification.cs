using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Storage;
using Microsoft.Azure.Storage.Blob;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.IO;
using System.Threading.Tasks;

namespace TestFunction
{
    public static class DecryptWithSignVerification
    {
        [FunctionName("BouncyCastleDecryptWithSign")]
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
                    CloudBlockBlob publicKey = container.GetBlockBlobReference("public.asc");

                    using (MemoryStream inputBlobStream = new MemoryStream())
                    using (Stream privateKeyStream = new MemoryStream())
                    using (Stream publicKeyStream = new MemoryStream())
                    {
                        byte[] arrayFile = null;
                        await blob.DownloadToStreamAsync(inputBlobStream);
                        await privateKey.DownloadToStreamAsync(privateKeyStream);
                        await publicKey.DownloadToStreamAsync(publicKeyStream);


                        var fileStream = DownloadAsFileStream(blob);

                        //PgpPrivateKey privateKeyP = ReadPrivateKey(privateKeyStream, passpharse);
                        PgpPublicKey senderPublicKey = ReadPublicKey(publicKeyStream);


                        //DecryptAndVerifySignature(inputBlobStream, decryptedStream, senderPublicKey, privateKeyP);
                        var decryptedData = DecryptAndVerifyFile(fileStream, senderPublicKey, null);

                        // Create a new blob for the encrypted data
                        CloudBlockBlob encryptedBlob = container.GetBlockBlobReference(data.DestinationFolderName + "/decrypted_" + file.Split("_")[1].Replace(".pgp", ""));

                        // Upload the encrypted data to the new blob
                        using (MemoryStream encryptedBlobStream = new MemoryStream(decryptedData))
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

        public static byte[] DecryptAndVerifyFile(FileStream inputFileStream, PgpPublicKey publicKey, PgpPrivateKey privateKey)
        {
            try
            {
                using (Stream inputStream = inputFileStream)
                {
                    using (MemoryStream decryptedDataStream = new MemoryStream())
                    {
                        PgpObjectFactory pgpFact = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
                        PgpObject pgpObject = pgpFact.NextPgpObject();

                        if (pgpObject is PgpCompressedData compressedData)
                        {
                            pgpFact = new PgpObjectFactory(compressedData.GetDataStream());

                            PgpObject message = pgpFact.NextPgpObject();

                            if (message is PgpLiteralData literalData)
                            {
                                Stream dataStream = literalData.GetInputStream();
                                dataStream.CopyTo(decryptedDataStream);
                                decryptedDataStream.Seek(0, SeekOrigin.Begin);
                                byte[] decryptedData = decryptedDataStream.ToArray();

                                // Verify signature
                                PgpObjectFactory remainingFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
                                PgpObject signatureObject = remainingFactory.NextPgpObject();

                                if (signatureObject is PgpSignatureList signature)
                                {
                                    if (signature != null)
                                    {
                                        signature[0].InitVerify(publicKey);

                                        using (Stream dataStreamSig = literalData.GetInputStream())
                                        {
                                            byte[] buffer = new byte[4096];
                                            int bytesRead;
                                            while ((bytesRead = dataStreamSig.Read(buffer, 0, buffer.Length)) > 0)
                                            {
                                                signature[0].Update(buffer, 0, bytesRead);
                                            }
                                        }

                                        if (signature[0].Verify())
                                        {
                                            Console.WriteLine("Signature verified successfully.");
                                            return decryptedData;
                                        }
                                        else
                                        {
                                            Console.WriteLine("Signature verification failed.");
                                        }
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("No signature found.");
                                }

                                return decryptedData;
                            }
                            else
                            {
                                Console.WriteLine("No compressed data found.");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (ex is PgpException pgpException)
                {
                    Console.WriteLine($"PGP Error: {pgpException.Message}");

                    // Check for specific algorithm errors
                    if (pgpException.Message.Contains("unknown public key algorithm"))
                    {
                        Console.WriteLine("Unsupported Algorithm - Details: {0}", pgpException.InnerException);
                    }
                }
                else
                {
                    Console.WriteLine($"An error occurred: {ex.Message}");
                }
            }

            return null;
        }

        // Extension method to read all bytes from a stream
        public static byte[] ReadAllBytes(this Stream stream)
        {
            using (MemoryStream memoryStream = new MemoryStream())
            {
                stream.CopyTo(memoryStream);
                return memoryStream.ToArray();
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

        private static PgpPublicKey ReadPublicKey(Stream publicKeyStream)
        {
            try
            {
                FileStream fileStream = ConvertStreamToFileStream(publicKeyStream);
                PgpPublicKeyRingBundle publicKeyRingBundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(fileStream));
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
}
