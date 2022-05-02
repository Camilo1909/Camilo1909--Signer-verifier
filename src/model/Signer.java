package model;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public class Signer {
	
	private static final int ITERACIONES = 1000;
	private String rute;
	private KeyPair keys;
	private InputStream fis;
	private FileInputStream privateK;
	private Signature sign; 
	private byte[] bytesSignature; 
	private byte[] file;
	
	public Signer(String rute, KeyPair keys) {
		this.rute = rute;
		this.keys = keys;
	}
	
	// Utilidad para desencriptar la clave privada con un password.El salto son los 8 primeros bytes del array que se pasa como texto cifrado.
	  private static byte[] decryptPrivateKey(char[] password, byte[] textEncrypt) throws Exception {
	    // Leer el salto.
	    byte[] jump = new byte[8];
	    ByteArrayInputStream bais = new ByteArrayInputStream(textEncrypt);
	    bais.read(jump,0,8);
	    // Los bytes resultantes son el texto cifrado.
	    byte[] remainigText = new byte[textEncrypt.length-8];
	    bais.read(remainigText,0,textEncrypt.length-8);
	    // Crear un descifrador PBE.
	    PBEKeySpec especification = new PBEKeySpec(password);
	    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
	    SecretKey key = factory.generateSecret(especification);
	    PBEParameterSpec parameters = new PBEParameterSpec(jump, ITERACIONES);
	    Cipher encryptor = Cipher.getInstance("PBEWithMD5AndDES");
	    // Realizar la desencriptacion
	    encryptor.init(Cipher.DECRYPT_MODE, key, parameters);
	    return encryptor.doFinal(remainigText);
	  }
	  //Metodo para firmar cualquier archivo.
	  public void SignFile() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		  BufferedReader br = new BufferedReader(new InputStreamReader(System.in)); //Ya tenemos el "lector"
		  System.out.println("Por favor ingrese la ruta del archivo que desea firmar:");//Se pide la ruta del archivo que se desea firmar al usuario
	      //Se lee la ruta del archivo
		  String path = br.readLine();
	      fis = new BufferedInputStream(new FileInputStream(path));
	      //Se lee el archivo
	      file = new byte[fis.available()];
	      fis.read(file);
	      //Se solicita el password de la clave privada para poder desencriptarla
	      System.out.print("Password para la clave privada:\n");
	      //Se lee la clave ingresada por el usuario
	        String password = br.readLine();
	        File pri = new File(rute);
	        //Se guarda la clave 
	        privateK = new FileInputStream(pri);
	        ByteArrayOutputStream baos = new ByteArrayOutputStream();
	        int b = 0;
	        while ((b = privateK.read()) != -1)
	        {
	          baos.write(b);
	        }
	        byte[] bytesClave  = baos.toByteArray();
	        // Aplicar PBE para obtener la clave
	        try {
	        	//Se intenta desencriptar el archivo con la clave dada por el usuario
				bytesClave = decryptPrivateKey(password.toCharArray(), bytesClave);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				//Si la clave dada por el usuario es incorrecta, se solicita nuevamente
				System.out.println("Contraseña incorrecta, ingresar clave de nuevo");
				System.out.print("Password para la clave privada: ");
		        password = br.readLine();
		        
			}
	        
	        sign = Signature.getInstance("MD5WithRSA");
	        sign.initSign(keys.getPrivate());
	        // Prepara la firma de los datos
	        sign.update(file);

	        // Firmar los datos
	        bytesSignature = sign.sign();
	        //Guarda el archivo firmado llam�ndolo "SignedFile"
	        ObjectOutputStream oos1 = new ObjectOutputStream(new FileOutputStream("SignedFile"));
	        oos1.writeObject(file);  
	        System.out.println("File signed");
	        oos1.close();
	        br.close();
	  }
	  
	public Signature getSign() {
		return sign;
	}
	public byte[] getArchivo() {
		return file;
	}
	public byte[] getBytesFirma() {
		return bytesSignature;
	}	
	
}
