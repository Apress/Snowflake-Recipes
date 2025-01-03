package com.snowrecipes.encryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;

/**
 * A barebones example on how to encrypt a file using AWS KMS and upload the file 
 * to AWS S3.
 *
 */
public class CSEWithKMS 
{
    public static void main( String[] args )
    {
    	String objectName = "test.dat"; //any object name that can be used to name the file in the object storage
        String bucketName = "<bucket name>";
        String objectPath = "<path to a csv file on your local machine>";
        String keyId = "1bb2ddd9-**************";
        String keyArn = "arn:aws:kms:us-east-2:296080767349:key/1bb2ddd9-****************";
        S3Client s3Client = null;


        AwsCrypto crypto = null;
        KmsMasterKeyProvider prov = null;
        
        try{
            s3Client = S3Client.builder()
                    .region(Region.US_EAST_2) //change the region if you are on a different region
                    .build();
            //AwsCrypto provides the primary entry-point to the AWS Encryption SDK. All encryption and decryption operations should start here. 
            crypto = AwsCrypto.builder()
                    .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
                    .build();
            prov = KmsMasterKeyProvider.builder().buildStrict(keyArn);
            

        }catch (RuntimeException nsae){
        	nsae.printStackTrace();
        }
        try{
        	System.out.println("Sending payload to s3");
        	
        	FileInputStream fileInputStream = null;
            byte[] bytesArray = null;

            try {
                File file = new File(objectPath);
                bytesArray = new byte[(int) file.length()];

                fileInputStream = new FileInputStream(file);
                fileInputStream.read(bytesArray);

            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (fileInputStream != null) {
                    try {
                        fileInputStream.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
            
            
            final Map<String, String> context = Collections.singletonMap("objectId", objectName);
            final CryptoResult<byte[], KmsMasterKey> encryptResult = crypto.encryptData(prov,
            		bytesArray, context);
            System.out.println(encryptResult.getMasterKeyIds());
            byte[] bytePayload  =  encryptResult.getResult();
            PutObjectRequest putOb = PutObjectRequest.builder()
                    .bucket(bucketName)
                    .key(objectName)
                    .build();

            PutObjectResponse response = s3Client.putObject(putOb, RequestBody.fromBytes(bytePayload));
            System.out.println(response);
        } catch (RuntimeException e){
            e.printStackTrace();
        }
    }
}
