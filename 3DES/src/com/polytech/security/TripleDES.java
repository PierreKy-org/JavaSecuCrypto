package com.polytech.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Vector;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class TripleDES {

	static public void main(String[] argv) {

		Provider prov = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		Security.addProvider(prov);

		try {

			if (argv.length > 0) {

				// Create a TripleDES object
				TripleDES the3DES = new TripleDES();

				if (argv[0].compareTo("-ECB") == 0) {
					// ECB mode
					// encrypt ECB mode
					Vector<SecretKey> Parameters = the3DES.encryptECB(
							new FileInputStream(new File(argv[1])), // clear text file
							new FileOutputStream(new File(argv[2])), // file encrypted
							"DES", // KeyGeneratorName
							"DES/ECB/NoPadding"); // CipherName
					// decrypt ECB mode
					the3DES.decryptECB(Parameters, // the 3 DES keys
							new FileInputStream(new File(argv[2])), // the encrypted file
							new FileOutputStream(new File(argv[3])), // the decrypted file
							"DES/ECB/NoPadding"); // CipherName
				} else if (argv[0].compareTo("-CBC") == 0) {
					// decryption
					// encrypt CBC mode
					Vector Parameters = the3DES.encryptCBC(
							new FileInputStream(new File(argv[1])), // clear text file
							new FileOutputStream(new File(argv[2])), // file encrypted
							"DES", // KeyGeneratorName
							"DES/CBC/NoPadding"); // CipherName
					// "DES/CBC/PKCS5Padding"); // CipherName
					// decrypt CBC mode
					the3DES.decryptCBC(
							Parameters, // the 3 DES keys
							new FileInputStream(new File(argv[2])), // the encrypted file
							new FileOutputStream(new File(argv[3])), // the decrypted file
							"DES/CBC/NoPadding"); // CipherName
					// "DES/CBC/PKCS5Padding"); // CipherName
				}

			}

			else {
				System.out.println("java TripleDES -ECB clearTextFile EncryptedFile DecryptedFile");
				System.out.println("java TripleDES -CBC clearTextFile EncryptedFile DecryptedFile");
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("java TripleDES -ECB clearTextFile EncryptedFile DecryptedFile");
			System.out.println("java TripleDES -CBC clearTextFile EncryptedFile DecryptedFile");
		}
	}

	/**
	 * 3DES ECB Encryption
	 */
	private Vector encryptECB(FileInputStream in,
			FileOutputStream out,
			String KeyGeneratorInstanceName,
			String CipherInstanceName) {
		try {

			// GENERATE 3 DES KEYS
			KeyGenerator kg = KeyGenerator.getInstance(KeyGeneratorInstanceName);
			SecretKey key1 = kg.generateKey();
			SecretKey key2 = kg.generateKey();
			SecretKey key3 = kg.generateKey();
			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR ENCRYPTION
			// WITH THE FIRST GENERATED DES KEY
			Cipher encryption1 = Cipher.getInstance(CipherInstanceName);
			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR DECRYPTION
			// WITH THE SECOND GENERATED DES KEY
			Cipher decryption = Cipher.getInstance(CipherInstanceName);
			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR ENCRYPTION
			// WITH THE THIRD GENERATED DES KEY
			Cipher encryption2 = Cipher.getInstance(CipherInstanceName);
			// GET THE MESSAGE TO BE ENCRYPTED FROM IN
			// CIPHERING
			// CIPHER WITH THE FIRST KEY
			// DECIPHER WITH THE SECOND KEY
			// CIPHER WITH THE THIRD KEY
			// write encrypted file

			encryption1.init(Cipher.ENCRYPT_MODE, key1);
			decryption.init(Cipher.DECRYPT_MODE, key2);
			encryption2.init(Cipher.ENCRYPT_MODE, key3);
			// FIleinputstream to string
			byte[] secretMessagesBytes = in.readAllBytes();

			byte[] encryptedMessageBytes = encryption1.doFinal(secretMessagesBytes);
			encryptedMessageBytes = decryption.doFinal(encryptedMessageBytes);
			encryptedMessageBytes = encryption2.doFinal(encryptedMessageBytes);

			// WRITE THE ENCRYPTED DATA IN OUT
			out.write(encryptedMessageBytes);
			// return the DES keys list generated
			Vector<SecretKey> keys = new Vector<SecretKey>();
			keys.add(key1);
			keys.add(key2);
			keys.add(key3);
			return keys;

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

	}

	/**
	 * 3DES ECB Decryption
	 */
	private void decryptECB(Vector Parameters,
			FileInputStream in,
			FileOutputStream out,
			String CipherInstanceName) {
		try {

			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR DECRYPTION
			// WITH THE THIRD GENERATED DES KEY
			Cipher decryption1 = Cipher.getInstance(CipherInstanceName);

			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR ENCRYPTION
			// WITH THE SECOND GENERATED DES KEY
			Cipher encryption = Cipher.getInstance(CipherInstanceName);

			// CREATE A DES CIPHER OBJECT FOR ENCRYPTION
			// WITH CipherInstanceName
			// FOR DECRYPTION
			// WITH THE FIRST GENERATED DES KEY
			Cipher decryption2 = Cipher.getInstance(CipherInstanceName);

			decryption1.init(Cipher.DECRYPT_MODE, (SecretKey) Parameters.get(2));
			encryption.init(Cipher.ENCRYPT_MODE, (SecretKey) Parameters.get(1));
			decryption2.init(Cipher.DECRYPT_MODE, (SecretKey) Parameters.get(0));

			// GET THE ENCRYPTED DATA FROM IN
			byte[] encryptedMessageBytes = in.readAllBytes();

			// DECIPHERING
			byte[] decryptedMessageBytes = decryption1.doFinal(encryptedMessageBytes);
			decryptedMessageBytes = encryption.doFinal(decryptedMessageBytes);
			decryptedMessageBytes = decryption2.doFinal(decryptedMessageBytes);
			// DECIPHER WITH THE THIRD KEY
			// CIPHER WITH THE SECOND KEY
			// DECIPHER WITH THE FIRST KEY
			//decryptedMessagesBytes to string
			String decode = new String(decryptedMessageBytes);

			// WRITE THE DECRYPTED DATA IN OUT
			out.write(decode.getBytes());

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * 3DES CBC Encryption
	 */
	private Vector encryptCBC(FileInputStream in,
			FileOutputStream out,
			String KeyGeneratorInstanceName,
			String CipherInstanceName) {
		try {

			// GENERATE 3 DES KEYS
			KeyGenerator kg = KeyGenerator.getInstance(KeyGeneratorInstanceName);
			SecretKey key1 = kg.generateKey();
			SecretKey key2 = kg.generateKey();
			SecretKey key3 = kg.generateKey();
			// GENERATE THE IV
			SecureRandom random = SecureRandom.getInstanceStrong();
			byte[] iv = new byte[8];
			random.nextBytes(iv);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);

			// CREATE A DES CIPHER OBJECT
			Cipher enc1 = Cipher.getInstance(CipherInstanceName);
			// WITH CipherInstanceName
			// FOR ENCRYPTION
			// WITH THE FIRST GENERATED DES KEY

			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR DECRYPTION
			// WITH THE SECOND GENERATED DES KEY
			Cipher dec = Cipher.getInstance(CipherInstanceName);

			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR ENCRYPTION
			// WITH THE THIRD GENERATED DES KEY

			Cipher enc2 = Cipher.getInstance(CipherInstanceName);
			// GET THE DATA TO BE ENCRYPTED FROM IN

			// CIPHERING

			// CIPHER WITH THE FIRST KEY
			// DECIPHER WITH THE SECOND KEY
			// CIPHER WITH THE THIRD KEY
			enc1.init(Cipher.ENCRYPT_MODE , key1, ivSpec);
			dec.init(Cipher.DECRYPT_MODE, key2, ivSpec);
			enc2.init(Cipher.ENCRYPT_MODE, key3, ivSpec);



			// WRITE THE ENCRYPTED DATA IN OUT
			byte[] secretMessageBytes = in.readAllBytes();
			byte[] encryptedMessageBytes = enc1.doFinal(secretMessageBytes);
			encryptedMessageBytes = dec.doFinal(encryptedMessageBytes);
			encryptedMessageBytes = enc2.doFinal(encryptedMessageBytes);
			out.write(encryptedMessageBytes);

			// return the DES keys list generated
			// return the DES keys list generated
			Vector<Object> parameters = new Vector();
			parameters.add(key1);
			parameters.add(key2);
			parameters.add(key3);
			parameters.add(ivSpec);
			return parameters;

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 3DES CBC Decryption
	 */
	private void decryptCBC(Vector Parameters,
			FileInputStream in,
			FileOutputStream out,
			String CipherInstanceName) {
		try {

			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR DECRYPTION
			// WITH THE THIRD GENERATED DES KEY
			Cipher decryption1 = Cipher.getInstance(CipherInstanceName);

			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR ENCRYPTION
			// WITH THE SECOND GENERATED DES KEY
			Cipher encryption = Cipher.getInstance(CipherInstanceName);

			// CREATE A DES CIPHER OBJECT FOR ENCRYPTION
			// WITH CipherInstanceName
			// FOR DECRYPTION
			// WITH THE FIRST GENERATED DES KEY
			Cipher decryption2 = Cipher.getInstance(CipherInstanceName);
			IvParameterSpec ivSpec = (IvParameterSpec) Parameters.get(3);

			decryption1.init(Cipher.DECRYPT_MODE, (SecretKey) Parameters.get(2),ivSpec);
			encryption.init(Cipher.ENCRYPT_MODE, (SecretKey) Parameters.get(1), ivSpec);
			decryption2.init(Cipher.DECRYPT_MODE, (SecretKey) Parameters.get(0),ivSpec);

			// GET THE ENCRYPTED DATA FROM IN
			byte[] encryptedMessageBytes = in.readAllBytes();

			// DECIPHERING
			byte[] decryptedMessageBytes = decryption1.doFinal(encryptedMessageBytes);
			decryptedMessageBytes = encryption.doFinal(decryptedMessageBytes);
			decryptedMessageBytes = decryption2.doFinal(decryptedMessageBytes);
			// DECIPHER WITH THE THIRD KEY
			// CIPHER WITH THE SECOND KEY
			// DECIPHER WITH THE FIRST KEY
			//decryptedMessagesBytes to string
			String decode = new String(decryptedMessageBytes);

			// WRITE THE DECRYPTED DATA IN OUT
			out.write(decode.getBytes());

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}