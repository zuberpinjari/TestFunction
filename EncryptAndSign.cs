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
using Org.BouncyCastle.Bcpg;
using Microsoft.Azure.Storage;
using Microsoft.Azure.Storage.Blob;

namespace TestFunction
{
    public static class EncryptAndSign
    {
        [FunctionName("EncryptAndSign")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            string inputFilePath = "C:\\Users\\xpinjajub\\Documents\\test.txt";
            string outputFilePath = "C:\\Users\\xpinjajub\\Documents\\encrypted_test.txt";
            string publicKeyFilePath = "C:\\Users\\xpinjajub\\Documents\\public.asc";
            string privateKeyFilePath = "C:\\Users\\xpinjajub\\Documents\\SECRET.asc";
            string decryptedFilePath = "C:\\Users\\xpinjajub\\Documents\\decrypted.txt";
            string passphrase = "abcd";


            //Blob Implementation
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


                }
            }



                    EncryptAndSignFile(inputFilePath, outputFilePath, publicKeyFilePath, privateKeyFilePath, passphrase);


            DecryptAndVerifyFile(outputFilePath, decryptedFilePath, publicKeyFilePath, privateKeyFilePath, passphrase);


            Console.WriteLine("Encryption and signing complete.");

            return new OkObjectResult("ok");
        }

        public static void EncryptAndSignFile(string inputFilePath, string outputFilePath, string publicKeyFilePath, string privateKeyFilePath, string passphrase)
        {
            try
            {
                using (Stream inputStream = File.OpenRead(inputFilePath))
                using (Stream encryptedOut = File.Create(outputFilePath))
                using (Stream publicKeyStream = File.OpenRead(publicKeyFilePath))
                using (Stream privateKeyStream = File.OpenRead(privateKeyFilePath))
                {
                    PgpPublicKey publicKey = ReadPublicKey(publicKeyFilePath);
                    PgpPrivateKey privateKey = ReadPrivateKey(privateKeyFilePath, passphrase);

                    using (MemoryStream compressedOut = new MemoryStream())
                    {
                        PgpCompressedDataGenerator compressor = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                        using (Stream compressedDataStream = compressor.Open(compressedOut))
                        {
                            PgpUtilities.WriteFileToLiteralData(compressedDataStream, PgpLiteralData.Binary, new FileInfo(inputFilePath));
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
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }


        public static void DecryptAndVerifyFile(string inputFilePath, string outputFilePath, string publicKeyFilePath, string privateKeyFilePath, string passphrase)
        {
            try
            {
                using (Stream inputStream = File.OpenRead(inputFilePath))
                using (Stream outputStream = File.Create(outputFilePath))
                using (Stream publicKeyStream = File.OpenRead(publicKeyFilePath))
                using (Stream privateKeyStream = File.OpenRead(privateKeyFilePath))
                {
                    PgpPublicKey publicKey = ReadPublicKey(publicKeyFilePath);
                    PgpPrivateKey privateKey = ReadPrivateKey(privateKeyFilePath, passphrase);

                    PgpObjectFactory pgpFact = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
                    PgpObject pgpObject = pgpFact.NextPgpObject();

                    if (pgpObject is PgpCompressedData compressedData)
                    {
                        pgpFact = new PgpObjectFactory(compressedData.GetDataStream());

                        PgpObject message = pgpFact.NextPgpObject();
                        
                        if (message is PgpLiteralData literalData)
                        {
                            Stream dataStream = literalData.GetInputStream();
                            dataStream.CopyTo(outputStream);
                            outputStream.Flush();

                            PgpObjectFactory remainingFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

                            PgpObject signatureObject = remainingFactory.NextPgpObject();
                           
                            if (signatureObject is PgpSignatureList signature)
                            {
                                if (signature != null)
                                {
                                    signature[0].InitVerify(publicKey);

                                    int ch;
                                    while ((ch = dataStream.ReadByte()) >= 0)
                                    {
                                        signature[0].Update((byte)ch);
                                        outputStream.WriteByte((byte)ch);
                                    }

                                    if (signature[0].Verify())
                                    {
                                        Console.WriteLine("Signature verified successfully.");
                                    }
                                    else
                                    {
                                        Console.WriteLine("Signature verification failed.");
                                    }
                                }
                            }
                            else
                            {
                                Console.WriteLine("No message found.");
                            }
                        }
                        else
                        {
                            Console.WriteLine("No compressed data found.");
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
        }

        public static PgpPublicKey ReadPublicKey(string publicKeyFilePath)
        {
            using (Stream keyIn = File.OpenRead(publicKeyFilePath))
            using (Stream inputStream = PgpUtilities.GetDecoderStream(keyIn))
            {
                PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

                // Iterate through the key rings and extract the public key
                foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
                {
                    foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                    {
                        if (key.IsEncryptionKey)
                        {
                            return key;
                        }
                    }
                }

                throw new Exception("Public key for encryption not found in the file");
            }
        }
        public static PgpPrivateKey ReadPrivateKey(string privateKeyFilePath, string passphrase)
        {
            using (Stream keyIn = File.OpenRead(privateKeyFilePath))
            using (Stream inputStream = PgpUtilities.GetDecoderStream(keyIn))
            {
                PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(inputStream);

                // Iterate through key rings
                foreach (PgpSecretKeyRing keyRing in pgpSec.GetKeyRings())
                {
                    // Get the secret key
                    PgpSecretKey secretKey = keyRing.GetSecretKey();

                    if (secretKey != null)
                    {
                        return secretKey.ExtractPrivateKey(passphrase.ToCharArray());
                    }
                }

                throw new Exception("Private key not found in the file");
            }
        }
        /*
        public static void DecryptAndVerifyFile1(string inputFilePath, string outputFilePath, string publicKeyFilePath, string privateKeyFilePath, string passphrase)
        {
            using (Stream inputStream = File.OpenRead(inputFilePath))
            using (Stream outputStream = File.Create(outputFilePath))
            using (Stream publicKeyStream = File.OpenRead(publicKeyFilePath))
            using (Stream privateKeyStream = File.OpenRead(privateKeyFilePath))
            {

                PgpObjectFactory pgpFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
                PgpObject obj = pgpFactory.NextPgpObject();

                // Handle encrypted data
                PgpEncryptedDataList encryptedDataList;
                if (obj is PgpEncryptedDataList)
                {
                    encryptedDataList = (PgpEncryptedDataList)obj;
                }
                else
                {
                    encryptedDataList = (PgpEncryptedDataList)pgpFactory.NextPgpObject();
                }

                // Find the matching secret key
                PgpPrivateKey privateKey = null;
                PgpPublicKeyEncryptedData encryptedData = null;
                foreach (PgpPublicKeyEncryptedData data in encryptedDataList.GetEncryptedDataObjects())
                {
                    privateKey = DecryptWithSignVerification.ReadPrivateKey(privateKeyStream, passphrase);
                    if (privateKey != null)
                    {
                        encryptedData = data;  // Capture the correct encryptedData 
                        break;
                    }
                }

                if (privateKey == null)
                {
                    throw new Exception("Matching private key not found.");
                }

                // Get input stream from encrypted data & verify signature
                Stream clearStream = encryptedData.GetDataStream(privateKey);
                PgpObjectFactory clearFactory = new PgpObjectFactory(clearStream);
                PgpOnePassSignature onePassSig = null;
                PgpObject message = clearFactory.NextPgpObject();

                // Signature verification
                if (message is PgpOnePassSignatureList)
                {
                    PgpOnePassSignatureList sigList = (PgpOnePassSignatureList)message;
                    onePassSig = sigList[0];

                    PgpPublicKey publicKey = BouncyCasleFunction.ReadPublicKey(publicKeyStream);
                    onePassSig.InitVerify(publicKey);

                    // Read data for signature calculation from the next object
                    message = clearFactory.NextPgpObject();
                }

                if (message is PgpCompressedData compressedData)
                {
                    PgpObjectFactory pgpCompressedFactory = new PgpObjectFactory(compressedData.GetDataStream());

                    // Get the next object (literal data) 
                    PgpObject pgpObject = pgpCompressedFactory.NextPgpObject();
                    if (pgpObject is PgpLiteralData literalData)
                    {
                        using (Stream literalDataStream = literalData.GetInputStream())
                        {
                            // Buffer for efficient copying
                            byte[] buffer = new byte[4096];
                            int bytesRead;

                            while ((bytesRead = literalDataStream.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                onePassSig.Update(buffer, 0, bytesRead);
                            }
                        }


                        // Get the next object (signature)
                        pgpObject = pgpCompressedFactory.NextPgpObject();
                        if (pgpObject is PgpSignatureList sigList)
                        {
                            PgpSignature signature = sigList[0];

                            if (!onePassSig.Verify(signature))
                            {
                                throw new Exception("Signature verification failed.");
                            }

                            // Process the literalDataStream here (it's your decrypted data)
                            using (Stream clearDataStream = literalData.GetInputStream())
                            {
                                clearDataStream.CopyTo(outputStream);
                            }
                        }
                    }
                    else
                    {
                        throw new Exception("Encrypted file format error.");
                    }
                }
            }
        }
        public static void DecryptAndVerifyFile2(string encryptedFilePath, string decryptedFilePath, string publicKeyFilePath, string privateKeyFilePath, string passphrase)
        {
            using (Stream inputStream = File.OpenRead(encryptedFilePath))
            using (Stream decryptedOut = File.Create(decryptedFilePath))
            using (Stream publicKeyStream = File.OpenRead(publicKeyFilePath))
            using (Stream privateKeyStream = File.OpenRead(privateKeyFilePath))
            {
                PgpObjectFactory pgpF = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

                // Loop through all objects until we find a suitable one
                PgpObject message = null;
                while (message == null && pgpF != null)
                {
                    PgpObject obj = pgpF.NextPgpObject();
                    if (obj == null)
                        break;
                    if (obj is PgpCompressedData)
                    {
                        PgpCompressedData cData = (PgpCompressedData)obj;
                        pgpF = new PgpObjectFactory(cData.GetDataStream());
                        continue;
                    }
                    if (obj is PgpEncryptedDataList)
                    {
                        PgpEncryptedDataList enc = (PgpEncryptedDataList)obj;
                        PgpPrivateKey privateKey = DecryptWithSignVerification.ReadPrivateKey(privateKeyStream, passphrase);
                        PgpPublicKeyEncryptedData pbe = (PgpPublicKeyEncryptedData)enc[0];

                        Stream clear = pbe.GetDataStream(privateKey);
                        PgpObjectFactory clearObjectFactory = new PgpObjectFactory(clear);
                        message = clearObjectFactory.NextPgpObject();
                        break;
                    }
                }
                if (message == null)
                    throw new PgpException("Message is not a simple encrypted file - type unknown.");

                if (message is PgpLiteralData)
                {
                    PgpLiteralData ld = (PgpLiteralData)message;
                    Stream output = ld.GetInputStream();
                    Streams.PipeAll(output, decryptedOut);
                }
                else if (message is PgpOnePassSignatureList)
                {
                    PgpOnePassSignatureList onePassList = (PgpOnePassSignatureList)message;
                    if (onePassList.Count > 0)
                    {
                        Console.WriteLine("Signature verified successfully.");
                    }
                }
                else
                {
                    throw new PgpException("Message is not a simple encrypted file - type unknown.");
                }
            }
        }
    }
        */
    }
}
