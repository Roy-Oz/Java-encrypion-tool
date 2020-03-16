package code;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;

public class DigitalSignatureDSA {
	private static final int READ_FILE_BUFFER_SIZE = 4096;
	private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256withRSA";
	private static final String DEFAULT_PROVIDER = "SunRsaSign";

	public DigitalSignatureDSA(){
	}
	// perform a digital signature on file, default algorithm is SHA256
	public byte[] GetSignatureOnFile(KeyStore keyStore, String filePath, String privateKeyAlias, String privateKeyPassword) throws NoSuchProviderException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, InvalidKeyException, IOException, SignatureException {
		Signature dsaInstance;
		PrivateKey privateKey;

		dsaInstance = Signature.getInstance(DEFAULT_SIGNATURE_ALGORITHM, DEFAULT_PROVIDER);
		privateKey = (PrivateKey) keyStore.getKey(privateKeyAlias, privateKeyPassword.toCharArray());
		dsaInstance.initSign(privateKey);

		File file = new File(filePath);
		FileInputStream is = new FileInputStream(file);
		byte[] buffer = new byte[READ_FILE_BUFFER_SIZE];
		while ((is.read(buffer)) != -1) {
			dsaInstance.update(buffer);
		}
		is.close();

		return dsaInstance.sign();
	}
	// verifying the signature
	public boolean verify(KeyStore keyStore, String alias, String filePath, byte[] signature) throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException, InvalidKeyException, IOException, SignatureException {
		Signature dsa;
		Certificate cert;

		dsa = Signature.getInstance(DEFAULT_SIGNATURE_ALGORITHM, DEFAULT_PROVIDER);
		cert = keyStore.getCertificate(alias);
		PublicKey pub = cert.getPublicKey();
		dsa.initVerify(pub);
		File file = new File(filePath);
		FileInputStream is = new FileInputStream(file);

		byte[] buffer = new byte[READ_FILE_BUFFER_SIZE];
		while ((is.read(buffer)) != -1) {
			dsa.update(buffer);
		}
		is.close();

		return  dsa.verify(signature);

	}
}
