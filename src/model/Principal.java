package model;

public class Principal {
	
	private KeyGenerator generateKey;
	private Signer signer;
	private Verifier verifier;
	
	public Principal() throws Exception{
		generateKey= new KeyGenerator();
		generateKey.createKeys();
		signer = new Signer(generateKey.getRuta(), generateKey.getClaves());
		signer.SignFile();
		verifier = new Verifier(signer.getSign(), generateKey.getClaves(),signer.getArchivo(),signer.getBytesFirma());
		verifier.VerifySign();

	}
	
	
}
