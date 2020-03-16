package code;

public class ConfigFile implements java.io.Serializable {
	public byte[] encodedKeySpec = null;
	public byte[] iv = null;
	public byte[] signature = null;

	public ConfigFile() {
	}

	public ConfigFile(byte[] encodedKeySpec, byte[] iv, byte[] signature)
	{
		this.encodedKeySpec = encodedKeySpec;
		this.iv = iv;
		this.signature = signature;
	}
}
