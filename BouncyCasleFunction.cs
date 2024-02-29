using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Microsoft.Azure.Storage;
using Microsoft.Azure.Storage.Blob;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using DidX.BouncyCastle.Utilities;

namespace TestFunction
{
    public static class BouncyCasleFunction
    {
        [FunctionName("EncryptFileBouncy")]
        public static async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
        ILogger log)
        {
            try
            {
                string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
                FileNames data = JsonConvert.DeserializeObject<FileNames>(requestBody);

                //Change container name here
                string containerName = "teststuff";
                var passpharse = "abcd";


                CloudStorageAccount storageAccount = CloudStorageAccount.Parse(Environment.GetEnvironmentVariable("AzureWebJobsStorage"));
                CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();
                CloudBlobContainer container = blobClient.GetContainerReference(containerName);
                foreach (var file in data.FileName)
                {
                    CloudBlockBlob blob = container.GetBlockBlobReference(file);
                    CloudBlockBlob publicKey = container.GetBlockBlobReference("public.asc");
                    CloudBlockBlob privateKey = container.GetBlockBlobReference("SECRET.asc");

                    using (Stream inputBlobStream = new MemoryStream())
                    using (Stream publicKeyStream = new MemoryStream())
                    using (Stream privateKeyStream = new MemoryStream())
                    {
                        await blob.DownloadToStreamAsync(inputBlobStream);
                        await publicKey.DownloadToStreamAsync(publicKeyStream);
                        await privateKey.DownloadToStreamAsync(privateKeyStream);



                        var fileStream = DownloadAsFileStream(blob);

                        // Your PGP encryption logic here
                        var encryptedData = EncryptStream(fileStream, publicKeyStream, privateKeyStream,passpharse );

                        // Create a new blob for the encrypted data
                        CloudBlockBlob encryptedBlob = container.GetBlockBlobReference(data.DestinationFolderName + "/encrypted_" + file + ".pgp");

                        await encryptedBlob.UploadFromStreamAsync(encryptedData);
                       
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

        public static FileStream EncryptStream(FileStream inputStream, Stream publicKeyStream, Stream privateKeyStream, string pwd)
        {
            try
            {
                // Read the public key from the stream
                PgpPublicKey publicKey = ReadPublicKey(publicKeyStream);
                PgpPrivateKey privateKey = BouncyCastleDecrypt.ReadPrivateKey(privateKeyStream, pwd);

                if (publicKey == null)
                {
                    Console.WriteLine("Public key not found or invalid.");
                    return null;
                }

                var tempFilePath = Path.GetTempFileName();
                // Create a memory stream to hold the encrypted data
                FileStream encryptedOutputStream = EncryptFileStream(inputStream, publicKey, privateKey);
                    // Return the encrypted data as a byte array
                    return encryptedOutputStream;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Encryption failed: {ex.Message}");
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
        public static PgpPublicKey ReadPublicKey(Stream publicKeyStream)
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


        public static FileStream EncryptFileStream(FileStream inputFileStream, PgpPublicKey publicKey, PgpPrivateKey privateKey)
        {
            try
            {
                string outputFilePath = Path.GetTempFileName();
                using (FileStream encryptedOut = File.Create(outputFilePath))
                {
                    using (MemoryStream compressedOut = new MemoryStream())
                    {
                        PgpCompressedDataGenerator compressor = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                        using (Stream compressedDataStream = compressor.Open(compressedOut))
                        {
                            PgpUtilities.WriteFileToLiteralData(compressedDataStream, PgpLiteralData.Binary, new FileInfo(inputFileStream.Name));
                        }

                        byte[] compressedData = compressedOut.ToArray();

                        // Write the compressed data to the output file
                        using (ArmoredOutputStream armoredOut = new ArmoredOutputStream(encryptedOut))
                        {
                            armoredOut.Write(compressedData, 0, compressedData.Length);
                        }

                        // Generate and write the signature
                        PgpSignatureGenerator signatureGenerator = new PgpSignatureGenerator(publicKey.Algorithm, HashAlgorithmTag.Sha256);
                        signatureGenerator.InitSign(PgpSignature.BinaryDocument, privateKey);

                        foreach (string userId in publicKey.GetUserIds())
                        {
                            PgpSignatureSubpacketGenerator subpacketGenerator = new PgpSignatureSubpacketGenerator();
                            subpacketGenerator.SetSignerUserId(false, userId);
                            signatureGenerator.SetHashedSubpackets(subpacketGenerator.Generate());
                            break; // Only take the first user ID
                        }

                        using (Stream signatureOut = new MemoryStream())
                        {
                            signatureGenerator.Generate().Encode(signatureOut);
                            byte[] signatureBytes = ((MemoryStream)signatureOut).ToArray();
                            using (ArmoredOutputStream armoredSignatureOut = new ArmoredOutputStream(encryptedOut))
                            {
                                armoredSignatureOut.Write(signatureBytes, 0, signatureBytes.Length);
                            }
                        }
                    }
                }

                return new FileStream(outputFilePath, FileMode.Open, FileAccess.Read);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
                return null; // Return null to indicate failure
            }
        }

        public static FileStream EncryptFileStream1(FileStream inputFileStream, PgpPublicKey publicKey, PgpPrivateKey privateKey, string password, string signerUserId)
        {
            try
            {
                // Output file path (same as input file path)
                string outputFilePath = Path.GetTempFileName();

                // Initialize a PgpEncryptedDataGenerator with the provided public key
                PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, true, new SecureRandom());
                encryptedDataGenerator.AddMethod(publicKey);

                // Create a PgpSignatureGenerator for signing
                PgpSignatureGenerator signatureGenerator = new PgpSignatureGenerator(publicKey.Algorithm, HashAlgorithmTag.Sha1);
                signatureGenerator.InitSign(PgpSignature.BinaryDocument, privateKey);
                foreach (string userId in publicKey.GetUserIds())
                {
                    PgpSignatureSubpacketGenerator spGen = new PgpSignatureSubpacketGenerator();
                    spGen.SetSignerUserId(false, userId);
                    signatureGenerator.SetHashedSubpackets(spGen.Generate());
                    // Just the first one!
                    break;
                }

                // Open the output file stream
                using (FileStream outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                {
                    // Open an encrypted stream with the output stream
                    using (Stream encryptedStream = encryptedDataGenerator.Open(outputStream, new byte[4096]))
                    {
                        // Copy data from the input file stream to the encrypted stream
                        inputFileStream.CopyTo(encryptedStream);

                        // Generate a one-pass signature
                        PgpOnePassSignature onePassSignature = signatureGenerator.GenerateOnePassVersion(false);

                        // Write the one-pass signature to the encrypted stream
                        onePassSignature.Encode(encryptedStream);
                    }
                }

                // Create a new FileStream for reading the encrypted file
                FileStream encryptedFileReadStream = new FileStream(outputFilePath, FileMode.Open, FileAccess.Read);

                // Return the FileStream for reading the encrypted file
                return encryptedFileReadStream;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Encryption failed: {ex.Message}");
                return null;
            }
        }



        /*
        public static FileStream EncryptFileStream(FileStream inputFileStream, PgpPublicKey publicKey, PgpPrivateKey privateKey, string password, string signerUserId)
        {
            try
            {
                // Output file path (same as input file path)
                string outputFilePath = Path.GetTempFileName();

                // Initialize a PgpEncryptedDataGenerator with the provided public key
                PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, true, new SecureRandom());
                encryptedDataGenerator.AddMethod(publicKey);

                // Create a new FileStream for the output file
                using (FileStream encryptedFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                {
                    // Open an encrypted stream with the new output file stream as the destination
                    using (Stream encryptedStream = encryptedDataGenerator.Open(encryptedFileStream, new byte[4096]))
                    {
                        // Copy data from the input file stream to the encrypted stream
                        inputFileStream.CopyTo(encryptedStream);
                    }

                    // Create a signature generator
                    PgpSignatureGenerator signatureGenerator = new PgpSignatureGenerator(publicKey.Algorithm, HashAlgorithmTag.Sha256);
                    signatureGenerator.InitSign(PgpSignature.BinaryDocument, privateKey);

                    // Create a subpacket containing the signer user ID
                    PgpSignatureSubpacketGenerator subpacketGenerator = new PgpSignatureSubpacketGenerator();
                    subpacketGenerator.SetSignerUserId(false, signerUserId);

                    // Add the signer user ID subpacket to the signature generator
                    signatureGenerator.SetHashedSubpackets(subpacketGenerator.Generate());

                    // Generate a one-pass signature
                    PgpOnePassSignature onePassSignature = signatureGenerator.GenerateOnePassVersion(false);

                    // Write the one-pass signature to the output file stream
                    onePassSignature.Encode(encryptedFileStream);

                    // Reset the position of the output file stream
                    encryptedFileStream.Position = 0;
                }

                // Create a new FileStream for reading the encrypted file
                FileStream encryptedFileReadStream = new FileStream(outputFilePath, FileMode.Open, FileAccess.Read);

                // Return the FileStream for reading the encrypted file
                return encryptedFileReadStream;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Encryption failed: {ex.Message}");
                return null;
            }
        }
        */
    }

}
