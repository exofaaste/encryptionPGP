package com.exofaaste;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.util.Base64;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
public class Encryption {
	//Following are the static properties for the encryption and decryption
	private static boolean isArmored = true;
	private static boolean integrityCheck = true;
	private static String publicKeyPath = "public key path";
	private static String privateKeyPath = "private key path";
	//Main
	public static void main(String[] args) throws NoSuchProviderException, IOException, PGPException {
		//This is the encryption
		System.out.println("Starting Encryption Main");
		String someStringToEncrypt = "Some text to encrypt";
		PgpProcessingUtil pgpProcessingUtil = new PgpProcessingUtil();
		byte[] finalOutput = null;
		InputStream publicKeyInputStream = new FileInputStream(publicKeyPath);
		PGPPublicKey pgpPublicKey = pgpProcessingUtil.readPublicKey(publicKeyInputStream);
		PGPEncryptionDataObject pgpEncryptionDataObject = new PGPEncryptionDataObject(someStringToEncrypt,
				pgpPublicKey, null, Boolean.TRUE, Boolean.TRUE);
		finalOutput = pgpProcessingUtil.encryptData(pgpEncryptionDataObject);
		System.out.println("This is the encrypted Message " + new String(finalOutput)  + "This is the Base64 Form " + Base64.getEncoder().encodeToString(finalOutput));
		
		//This is the decryption call 
		System.out.println("Starting Decryption Main");
		byte[] decryptedOutput = null;
		InputStream privateKeyInputStream = new FileInputStream(privateKeyPath);
		String privateKeySecret = new String("Some Password Here".getBytes("UTF-8"), "UTF-8");
		PGPDecryptionDataObject pgpDecryptionDataObject = new PGPDecryptionDataObject(finalOutput,
				privateKeyInputStream, privateKeySecret.toCharArray());
		decryptedOutput = pgpProcessingUtil.decrypt(pgpDecryptionDataObject);
		System.out.println("This is the Decrypted Message " + new String(decryptedOutput));
	}


}
