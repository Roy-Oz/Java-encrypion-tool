package code;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Main {
	private static final String ENCRYPT_MODE = "ENCRYPT";
	private static final String DECRYPT_MODE = "DECRYPT";
	private static final String KEYSTORE_FORMAT = "PKCS12";

	public static void main(String[] args) throws Exception {
		if (args.length != 9) {
			System.out.println("usage: project.jar <mode> <input_path> <output_path> <keystore_path> <keystore_password> <public_key_alias_of_other_side> <config_path> <private_key_alias_of_you> <private_key_password_of_you>");
			System.exit(1);
		}

		String mode = args[0];
		String inputPath = args[1];
		String outputPath = args[2];
		String keyStorePath = args[3];
		String keyStorePassword = args[4];
		String publicKeyAliasOfOtherSide = args[5];
		String configPath = args[6];
		String privateKeyAliasOfYou = args[7];
		String privateKeyPasswordOfYou = args[8];

		KeyStore keyStore = GetKeyStore(keyStorePath, keyStorePassword);

		if (mode.toUpperCase().equals(ENCRYPT_MODE)) {
			System.out.println("Entering ENCRYPT_MODE");

			FileEncryptor fileEncryptor = new FileEncryptor(keyStore, privateKeyAliasOfYou, privateKeyPasswordOfYou, publicKeyAliasOfOtherSide);
			fileEncryptor.StartEncrypt(inputPath, outputPath, configPath);

		} else if(mode.toUpperCase().equals(DECRYPT_MODE)) {
			System.out.println("Entering DECRYPT_MODE");

			FileDecryptor fileDecryptor = new FileDecryptor(keyStore, configPath, privateKeyAliasOfYou, privateKeyPasswordOfYou);
			Boolean verified = fileDecryptor.DecryptAndIsVerify(inputPath, outputPath, publicKeyAliasOfOtherSide);

			if (verified) {
				System.out.printf("Verified! See decrypted file at %s\n", outputPath);
			}

		} else {
			System.out.println("mode should be Encrypt/decrypt");
			System.exit(1);
		}
	}

	private static KeyStore GetKeyStore(String keyStorePath, String keyStorePassword) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
		KeyStore keyStore = KeyStore.getInstance(KEYSTORE_FORMAT);
		InputStream ksData = new FileInputStream(keyStorePath);
		keyStore.load(ksData, keyStorePassword.toCharArray());

		return keyStore;
	}


}