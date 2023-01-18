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
			String secretMessage = new String(in.readAllBytes());

			byte[] secretMessagesBytes = secretMessage.getBytes(StandardCharsets.UTF_8);

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
