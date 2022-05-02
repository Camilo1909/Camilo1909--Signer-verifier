package model;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public class KeyGenerator {
	
	private static final int ITERACIONES = 1000;
	private String path;
	private KeyPair keys;  
	   
		  // Crea una clave RSA de 1024 bits y la almacena en dos ficheros
		  // uno para la publica y otro para la privada (encriptada por password)
		  public void createKeys() throws Exception {
		    // Crear la clave RSA
		    System.out.println("Generando el par de claves RSA.");
		    KeyPairGenerator generatorRSA = KeyPairGenerator.getInstance("RSA");
		    generatorRSA.initialize(1024);
		    keys = generatorRSA.genKeyPair();
		    // Toma la forma codificada de la clave publica para usarla en el futuro. 
		    byte[] bytesPublic = keys.getPublic().getEncoded();
		    // Lee el nombre del archivo para la clave publica
		    System.out.print("Nombre del archivo para grabar la clave publica:\n");
		    BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
		    String filePublic = input.readLine();
		    // Escribir la clave publica codificada en su fichero
		    FileOutputStream output = new FileOutputStream(filePublic);
		    output.write(bytesPublic);
		    output.close();
		    // Repetimos lo mismo para la clave privada, encriptandola con un password.
		    System.out.print("Nombre del archivo para grabar la clave privada:\n");
		    String filePrivate = input.readLine();
		    //Guardamos la ruta de la clave privada para usarla posteriormente
		    path = "C:/Users/kmilo/OneDrive/Documentos/8-Semestre/Seguridad/Proyecto final/Signer-verifier/" + filePrivate + "";
		    // Tomamos la forma codificada. 
		    byte[] bytesPrivate = keys.getPrivate().getEncoded();
		    // Solicitar el password para encriptar la clave privada
		    System.out.print("Password para encriptar la clave privada:\n");
		    String password = input.readLine();
		    // Aqui encriptamos la clave privada
		    byte[] bytesPrivateEncrypt =
		    encryptPrivateKey(password.toCharArray(),bytesPrivate);
		    // Grabamos el resultado en el fichero
		    output = new FileOutputStream(filePrivate);
		    output.write(bytesPrivateEncrypt);
		    output.close();
		  }
		  // Utilidad para encriptar la clave privada con un password. El salto seran los 8 primeros bytes del array devuelto.
		  private static byte[] encryptPrivateKey(char[] password, byte[] text) throws Exception {
		    // Crear el salto
		    byte[] jump = new byte[8];
		    Random random = new Random();
		    random.nextBytes(jump);
		    // Crear una clave y un cifrador PBE
		    PBEKeySpec especification = new PBEKeySpec(password);
		    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
		    SecretKey key = factory.generateSecret(especification);
		    PBEParameterSpec parametros = new PBEParameterSpec(jump, ITERACIONES);
		    Cipher encryptor = Cipher.getInstance("PBEWithMD5AndDES");
		    encryptor.init(Cipher.ENCRYPT_MODE, key, parametros);
		    // Encriptar el array
		    byte[] textEncrypt = encryptor.doFinal(text);
		    // Escribir el salto seguido del texto cifrado y devolverlo.
		    ByteArrayOutputStream baos = new ByteArrayOutputStream();
		    baos.write(jump);
		    baos.write(textEncrypt);
		    return baos.toByteArray();
		  }	
		  
		  public String getRuta() {
				return path;
		  }
		  
		public KeyPair getClaves() {
			return keys;
		}  
}

