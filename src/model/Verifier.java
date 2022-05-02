package model;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import javax.crypto.NoSuchPaddingException;

public class Verifier {
	
	private Signature sign;
	private KeyPair keys;
	private byte[] file;
	private byte[] bytesSignature;
	
	public Verifier(Signature sign ,KeyPair keys, byte[] file, byte[] bytesSignature) {
		this.sign = sign;
		this.keys = keys;
		this.file = file;
		this.bytesSignature = bytesSignature;
	}
	
	 //Verificar que el archivo se ha firmado correctamente
	  public void VerifySign() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, SignatureException, IOException {
		  //Inicializa la clave publica para la verificacion
		  sign.initVerify(keys.getPublic());
		  //Actualiza el archivo que se va a verificar
		  sign.update(file);
		  boolean verify = false;
		  try {
			  //Verifica la ultima firma
		    verify = sign.verify(bytesSignature);
		  } catch (SignatureException se) {
		        verify = false;
		    }

		  if (verify) {
		    System.out.println("Siganture verificada.");
		  } else {
		    System.out.println("Siganture incorrect.");
		  }
	  }

}
