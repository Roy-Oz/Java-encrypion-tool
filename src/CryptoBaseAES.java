package code;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;

public class CryptoBaseAES {
	private static final int CIPHER_OUTPUT_BUFFER_SIZE = 4096;
	private static final String DEFAULT_RANDOM_ALGORITHM = "SHA1PRNG";
	private static final String DEFAULT_PROVIDER = "SunJCE";
	private static final String DEFAULT_TRANSFORMATION = "AES/CTR/PKCS5Padding";
	private static final String SECRET_KEY_SPEC_ALGORITHM = "AES";

	private static final int KEY_SIZE_BYTES = 256 / 8;
	private static final int IV_SIZE_BYTES = 128 / 8;

	private SecretKeySpec keySpec;
	private IvParameterSpec ivSpec;

	private Cipher encryptor;
	private Cipher decryptor;

	// generates all the necessary parts for encryption, using default algorithms specified above
	public CryptoBaseAES() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
		RandomGenerator randomGenerator = new RandomGenerator();

		byte[] key = randomGenerator.GenerateRandomBytes(DEFAULT_RANDOM_ALGORITHM, KEY_SIZE_BYTES);
		byte[] iv = randomGenerator.GenerateRandomBytes(DEFAULT_RANDOM_ALGORITHM, IV_SIZE_BYTES);

		encryptor = Cipher.getInstance(DEFAULT_TRANSFORMATION, DEFAULT_PROVIDER);


		keySpec = new SecretKeySpec(key, SECRET_KEY_SPEC_ALGORITHM);
		ivSpec = new IvParameterSpec(iv);

		encryptor.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
	}

	public CryptoBaseAES(byte[] key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException {
		decryptor = Cipher.getInstance(DEFAULT_TRANSFORMATION, DEFAULT_PROVIDER);

		keySpec = new SecretKeySpec(key, SECRET_KEY_SPEC_ALGORITHM);
		ivSpec = new IvParameterSpec(iv);

		decryptor.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
	}
	// perform the encryption process
	public void Encrypt(String inputPath, String outputPath) throws IOException {
		FileInputStream fileInputStream = new FileInputStream(inputPath);
		FileOutputStream fileOutputStream = new FileOutputStream(outputPath);
		CipherOutputStream cipherOutputStream = new CipherOutputStream(fileOutputStream, encryptor);

		byte[] buffer = new byte[CIPHER_OUTPUT_BUFFER_SIZE];
		int bufferIndex;

		while ((bufferIndex = fileInputStream.read(buffer)) != -1) {
			cipherOutputStream.write(buffer, 0, bufferIndex);
		}

		cipherOutputStream.close();
		fileOutputStream.close();
		fileInputStream.close();
	}



	public Cipher getEncryptor() {
		return encryptor;
	}

	public Cipher getDecryptor() {
		return decryptor;
	}

	public SecretKeySpec getKeySpec() {
		return keySpec;
	}

	public IvParameterSpec getIvSpec() {
		return ivSpec;
	}
}
