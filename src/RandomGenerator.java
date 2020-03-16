package code;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

// generates rand random stream of bytes by a specific length and algorithm
public class RandomGenerator {
	public byte[] GenerateRandomBytes(String algorithm, int length) throws NoSuchAlgorithmException {
		SecureRandom secureRandom = SecureRandom.getInstance(algorithm);
		byte[] randomBytes = new byte[length];
		secureRandom.nextBytes(randomBytes);
		return randomBytes;
	}
}
