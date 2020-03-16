package code;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class CryptoBaseRSA {
	private static final String DEFAULT_PROVIDER = "SunJCE";
	private static final String DEFAULT_TRANSFORMATION = "RSA/ECB/PKCS1PADDING";

	private Cipher encryptor;
	private Cipher decryptor;
	// RSA ECB mode for encrypting the symmetric key
	public CryptoBaseRSA(PrivateKey privateKey, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
		decryptor = Cipher.getInstance(DEFAULT_TRANSFORMATION, DEFAULT_PROVIDER);
		encryptor = Cipher.getInstance(DEFAULT_TRANSFORMATION, DEFAULT_PROVIDER);

		if (publicKey != null) {
			encryptor.init(Cipher.ENCRYPT_MODE, publicKey);
		}
		if (privateKey != null) {
			decryptor.init(Cipher.DECRYPT_MODE, privateKey);
		}
	}

	public byte[] Encrypt(byte[] input) throws BadPaddingException, IllegalBlockSizeException {
		return encryptor.doFinal(input);
	}

	public byte[] Decrypt(byte[] input) throws BadPaddingException, IllegalBlockSizeException {
		return decryptor.doFinal(input);
	}


	public Cipher getEncryptor() {
		return encryptor;
	}

	public Cipher getDecryptor() {
		return decryptor;
	}
}
