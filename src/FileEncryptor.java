package code;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;

public class FileEncryptor {
	private CryptoBaseAES baseAES;
	private CryptoBaseRSA baseRSA;
	private DigitalSignatureDSA dsDSA;

	private KeyStore keyStore;
	private String privateKeyAlias;
	private String privateKeyPassword;
	private byte[] signature;

	public FileEncryptor(KeyStore keyStore, String privateKeyAlias,
						 String privateKeyPassword, String otherPublicKeyAlias) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, KeyStoreException, UnrecoverableKeyException {
		this.keyStore = keyStore;
		this.privateKeyAlias = privateKeyAlias;
		this.privateKeyPassword = privateKeyPassword;

		baseAES = new CryptoBaseAES();

		Certificate certificate =
				keyStore.getCertificate(otherPublicKeyAlias);
		PublicKey publicKey = certificate.getPublicKey();

		baseRSA = new CryptoBaseRSA(null, publicKey);

		dsDSA = new DigitalSignatureDSA();

	}

	public void StartEncrypt(String inputPath, String outputPath, String configPath) throws IOException, BadPaddingException, IllegalBlockSizeException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, SignatureException, NoSuchProviderException, InvalidKeyException {
		baseAES.Encrypt(inputPath, outputPath);		// encrypting the file with symmetric encryption

		// signing the file
		this.signature = dsDSA.GetSignatureOnFile(this.keyStore, outputPath, this.privateKeyAlias, this.privateKeyPassword);

		// save thr data to config file for other side
		finalizeConfig(configPath);
	}

	private void finalizeConfig(String configPath) throws BadPaddingException, IllegalBlockSizeException, IOException {
		ConfigFile configFile;
		byte[] encodedKeySpec = baseRSA.Encrypt(baseAES.getKeySpec().getEncoded());

		if (this.signature == null ) {
			throw new IOException("signature is null! can't save config");
		}
		// writing to config file the encrypted symmetric key, IV and digital signature
		configFile = new ConfigFile(encodedKeySpec, baseAES.getIvSpec().getIV(), this.signature);

		FileOutputStream fileOutputStream = new FileOutputStream(configPath);
		ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
		objectOutputStream.writeObject(configFile);

		objectOutputStream.close();
		fileOutputStream.close();
	}
}
