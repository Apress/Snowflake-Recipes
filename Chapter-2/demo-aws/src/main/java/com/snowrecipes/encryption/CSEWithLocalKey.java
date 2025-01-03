package com.snowrecipes.encryption;

import java.io.File;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3Encryption;
import com.amazonaws.services.s3.AmazonS3EncryptionClientBuilder;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;

/**
 * A barebones example on how to encrypt a file using a local key and upload the file 
 * to AWS S3.
 *
 */
public class CSEWithLocalKey {
	public static final int AES_KEY_SIZE = 256;
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_LENGTH = 16;

    public static void main(String[] args) throws Exception
    {
    	
        String objectName = "test.dat"; //any object name that can be used to name the file in the object storage
        String bucketName = "<bucket name>";
        String objectPath = "<path to a csv file on your local machine>";
         
        System.out.println("calling encryption with customer managed keys");
    
        SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
        
        // Key to String: get base64 encoded version of the key
        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        System.out.println(encodedKey);
        // String to Key: decode the base64 encoded string
        //byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        // rebuild key using SecretKeySpec
        //SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES"); 
        
        AmazonS3Encryption s3Encryption = AmazonS3EncryptionClientBuilder
                .standard()
                .withRegion(Regions.US_EAST_2) //change the region if you are on a different region
                .withCryptoConfiguration(new CryptoConfiguration(CryptoMode.EncryptionOnly))
                .withEncryptionMaterials(new StaticEncryptionMaterialsProvider(new EncryptionMaterials(secretKey)))
                .build();

        s3Encryption.putObject(bucketName, objectName, new File(objectPath));

        System.out.println(s3Encryption.getObjectAsString(bucketName, objectName));

    }
    
}
