package code;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;

public class FileDecryptor {
	private CryptoBaseAES baseAES;
	private CryptoBaseRSA baseRSA;
	private DigitalSignatureDSA dsDSA;
	private KeyStore keyStore;
	private ConfigFile configFile;

	private static final int CHUNK_SIZE = 4096;

	public FileDecryptor(KeyStore keyStore, String configPath,
						 String privateKeyAlias, String privateKeyPassword) throws NoSuchProviderException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableKeyException, KeyStoreException, IOException, ClassNotFoundException {

		this.keyStore = keyStore;

		PrivateKey privateKey = (PrivateKey) this.keyStore.getKey(privateKeyAlias,
				privateKeyPassword.toCharArray());

		baseRSA = new CryptoBaseRSA(privateKey, null);

		this.configFile = loadConfig(configPath);
	}

	private ConfigFile loadConfig(String configPath) throws IOException, ClassNotFoundException {
		System.out.printf("Loading config file: %s\n", configPath);

		FileInputStream fileInputStream = new FileInputStream(configPath);
		ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);

		return (ConfigFile) objectInputStream.readObject();
	}

	public boolean DecryptAndIsVerify(String filePath, String outputPath, String PublicKeyOfOtherSideAlias) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
		byte[] encodedKeySpec = baseRSA.Decrypt(configFile.encodedKeySpec);

		baseAES = new CryptoBaseAES(encodedKeySpec, configFile.iv);

		FileInputStream fileInputStream = new FileInputStream(filePath);
		FileOutputStream fileOutputStream = new FileOutputStream(outputPath);
		CipherOutputStream cipherOutputStream = new CipherOutputStream(fileOutputStream, baseAES.getDecryptor());

		System.out.printf("Decrypting file: %s\n", filePath);
		byte[] chunk = new byte[CHUNK_SIZE];
		int chunkLength;
		while ((chunkLength = fileInputStream.read(chunk)) != -1) {
			cipherOutputStream.write(chunk, 0, chunkLength);
		}

		cipherOutputStream.close();
		fileOutputStream.close();
		fileInputStream.close();

		dsDSA = new DigitalSignatureDSA();

		System.out.printf("Verifying file: %s\n", filePath);
		return dsDSA.verify(this.keyStore, PublicKeyOfOtherSideAlias, filePath, configFile.signature);
	}
}
