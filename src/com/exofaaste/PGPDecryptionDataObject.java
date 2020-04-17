package com.exofaaste;

import java.io.InputStream;

public class PGPDecryptionDataObject {

	private byte[] encryptedDataAsByteArray;
	private InputStream privateKeyAsStream;
	private char[] secret;

	public PGPDecryptionDataObject(byte[] encryptedDataAsByteArray, InputStream privateKeyAsStream, char[] secret) {
		super();
		this.encryptedDataAsByteArray = encryptedDataAsByteArray;
		this.privateKeyAsStream = privateKeyAsStream;
		this.secret = secret;
	}

	public byte[] getEncryptedDataAsByteArray() {
		return encryptedDataAsByteArray;
	}

	public void setEncryptedDataAsByteArray(byte[] encryptedDataAsByteArray) {
		this.encryptedDataAsByteArray = encryptedDataAsByteArray;
	}

	public InputStream getPrivateKeyAsStream() {
		return privateKeyAsStream;
	}

	public void setPrivateKeyAsStream(InputStream privateKeyAsStream) {
		this.privateKeyAsStream = privateKeyAsStream;
	}

	public char[] getSecret() {
		return secret;
	}

	public void setSecret(char[] secret) {
		this.secret = secret;
	}
}
