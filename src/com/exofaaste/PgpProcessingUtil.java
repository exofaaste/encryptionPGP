package com.exofaaste;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

public class PgpProcessingUtil {
	
	public byte[] encryptData(PGPEncryptionDataObject pgpEncryptionDataObject)
			throws IOException, PGPException, NoSuchProviderException {

		pgpEncryptionDataObject.setOutputFileName(PGPLiteralData.CONSOLE);
		byte[] dataToBeEncryptedAsArray = pgpEncryptionDataObject.getDataToBeEncrypted().getBytes();
		ByteArrayOutputStream encryptedDataAsByteArrayOutputStream = new ByteArrayOutputStream();

		OutputStream encryptedDataAsOutputStream = encryptedDataAsByteArrayOutputStream;

		if (pgpEncryptionDataObject.getIsDataArmored()) {
			encryptedDataAsOutputStream = new ArmoredOutputStream(encryptedDataAsOutputStream);
		}

		ByteArrayOutputStream compressedDataByteArrayOutputStream = new ByteArrayOutputStream();

		PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(
				PGPCompressedDataGenerator.ZIP);
		OutputStream compressedDataStream = compressedDataGenerator.open(compressedDataByteArrayOutputStream);
		PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();

		OutputStream compressedDataOutputStream = literalDataGenerator.open(compressedDataStream, PGPLiteralData.TEXT,
				pgpEncryptionDataObject.getOutputFileName(), dataToBeEncryptedAsArray.length, new Date());
		compressedDataOutputStream.write(dataToBeEncryptedAsArray);

		compressedDataStream.close();
		literalDataGenerator.close();
		compressedDataGenerator.close();

		PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
				new BcPGPDataEncryptorBuilder(PGPEncryptedData.AES_256));

		encryptedDataGenerator
				.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(pgpEncryptionDataObject.getPublicKey()));

		byte[] bytes = compressedDataByteArrayOutputStream.toByteArray();

		OutputStream finalEncryptedDataOutputStream = encryptedDataGenerator.open(encryptedDataAsOutputStream,
				bytes.length);

		finalEncryptedDataOutputStream.write(bytes);

		finalEncryptedDataOutputStream.close();

		encryptedDataAsOutputStream.close();

		return encryptedDataAsByteArrayOutputStream.toByteArray();
	}
	public byte[] decrypt(PGPDecryptionDataObject pgpDecryptionDataObject)
			throws IOException, PGPException, NoSuchProviderException {

		InputStream encryptedDataAsInputStream = new ByteArrayInputStream(
				pgpDecryptionDataObject.getEncryptedDataAsByteArray());

		encryptedDataAsInputStream = PGPUtil.getDecoderStream(encryptedDataAsInputStream);

		BcKeyFingerprintCalculator bcKeyFingerprintCalculator = new BcKeyFingerprintCalculator();

		PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(encryptedDataAsInputStream,
				bcKeyFingerprintCalculator);
		PGPEncryptedDataList pgpEncryptedDataListObj = null;
		Object encryptedDataAsObject = pgpObjectFactory.nextObject();

		// the first object might be a PGP marker packet.
		if (encryptedDataAsObject instanceof PGPEncryptedDataList) {
			pgpEncryptedDataListObj = (PGPEncryptedDataList) encryptedDataAsObject;
		} else {
			pgpEncryptedDataListObj = (PGPEncryptedDataList) pgpObjectFactory.nextObject();
		}

		// find the secret key
		Iterator it = pgpEncryptedDataListObj.getEncryptedDataObjects();
		PGPPrivateKey pgpPrivateKey = null;
		PGPPublicKeyEncryptedData pgpPublickeytEncryptedData = null;
		PGPSecretKeyRingCollection pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(
				PGPUtil.getDecoderStream(pgpDecryptionDataObject.getPrivateKeyAsStream()), bcKeyFingerprintCalculator);

		while (pgpPrivateKey == null && it.hasNext()) {
			pgpPublickeytEncryptedData = (PGPPublicKeyEncryptedData) it.next();
			pgpPrivateKey = findSecretKey(pgpSecretKeyRingCollection, pgpPublickeytEncryptedData.getKeyID(),
					pgpDecryptionDataObject.getSecret());
		}

		if (pgpPrivateKey == null) {
			throw new IllegalArgumentException("secret key for message not found.");
		}

		InputStream pgpEncryptedDataAsInputStream = pgpPublickeytEncryptedData
				.getDataStream(new BcPublicKeyDataDecryptorFactory(pgpPrivateKey));

		PGPObjectFactory pgpObjectFactory2 = new PGPObjectFactory(pgpEncryptedDataAsInputStream,
				bcKeyFingerprintCalculator);

		PGPCompressedData pgpCompressedData = (PGPCompressedData) pgpObjectFactory2.nextObject();

		pgpObjectFactory2 = new PGPObjectFactory(pgpCompressedData.getDataStream(), bcKeyFingerprintCalculator);

		PGPLiteralData pgpLiteralData = (PGPLiteralData) pgpObjectFactory2.nextObject();

		InputStream literalDataAsStream = pgpLiteralData.getInputStream();

		ByteArrayOutputStream finalByteArrayOutputStream = new ByteArrayOutputStream();
		int ch;

		while ((ch = literalDataAsStream.read()) >= 0) {
			finalByteArrayOutputStream.write(ch);
		}

		encryptedDataAsInputStream.close();
		finalByteArrayOutputStream.close();

		return finalByteArrayOutputStream.toByteArray();
	}

	public PGPPublicKey readPublicKey(InputStream publicKeyAsInputStream) throws IOException, PGPException {
		publicKeyAsInputStream = PGPUtil.getDecoderStream(publicKeyAsInputStream);

		BcKeyFingerprintCalculator bcKeyFingerprintCalculator = new BcKeyFingerprintCalculator();
		PGPPublicKeyRingCollection pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(publicKeyAsInputStream,
				bcKeyFingerprintCalculator);
		Iterator<PGPPublicKeyRing> pgpPublicKeyRingsCollectionIterator = pgpPublicKeyRingCollection.getKeyRings();

		while (pgpPublicKeyRingsCollectionIterator.hasNext()) {
			PGPPublicKeyRing pgpPublicKeyRing = (PGPPublicKeyRing) pgpPublicKeyRingsCollectionIterator.next();
			Iterator<PGPPublicKey> pgpPublicKeyRingIterator = pgpPublicKeyRing.getPublicKeys();

			while (pgpPublicKeyRingIterator.hasNext()) {
				PGPPublicKey pgpPublicKey = (PGPPublicKey) pgpPublicKeyRingIterator.next();

				if (pgpPublicKey.isEncryptionKey()) {
					return pgpPublicKey;
				}
			}
		}

		throw new IllegalArgumentException("Can't find encryption key in key ring.");
	}
	
	private static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSecretKeyRingCollection, long secretKeyID,
			char[] secret) throws PGPException, NoSuchProviderException {
		PGPSecretKey pgpSecretKey = pgpSecretKeyRingCollection.getSecretKey(secretKeyID);

		if (pgpSecretKey == null) {
			return null;
		}

		PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
				.build(secret);

		return pgpSecretKey.extractPrivateKey(decryptor);
	}
}
