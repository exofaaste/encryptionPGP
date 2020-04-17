package com.exofaaste;

import org.bouncycastle.openpgp.PGPPublicKey;

public class PGPEncryptionDataObject {

	private String dataToBeEncrypted;
	private PGPPublicKey publicKey;
	private String outputFileName;
	private Boolean isIntegrityCheckRequired;
	private Boolean isDataArmored;

	public PGPEncryptionDataObject(String dataToBeEncrypted, PGPPublicKey publicKey, String outputFileName,
			Boolean isIntegrityCheckRequired, Boolean isDataArmored) {
		super();
		this.dataToBeEncrypted = dataToBeEncrypted;
		this.publicKey = publicKey;
		this.outputFileName = outputFileName;
		this.isIntegrityCheckRequired = isIntegrityCheckRequired;
		this.isDataArmored = isDataArmored;
	}

	public String getDataToBeEncrypted() {
		return dataToBeEncrypted;
	}

	public void setDataToBeEncrypted(String dataToBeEncrypted) {
		this.dataToBeEncrypted = dataToBeEncrypted;
	}

	public PGPPublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PGPPublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public String getOutputFileName() {
		return outputFileName;
	}

	public void setOutputFileName(String outputFileName) {
		this.outputFileName = outputFileName;
	}

	public Boolean getIsIntegrityCheckRequired() {
		return isIntegrityCheckRequired;
	}

	public void setIsIntegrityCheckRequired(Boolean isIntegrityCheckRequired) {
		this.isIntegrityCheckRequired = isIntegrityCheckRequired;
	}

	public Boolean getIsDataArmored() {
		return isDataArmored;
	}

	public void setIsDataArmored(Boolean isDataArmored) {
		this.isDataArmored = isDataArmored;
	}

}
