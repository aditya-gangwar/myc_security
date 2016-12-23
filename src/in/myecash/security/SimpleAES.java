package in.myecash.security;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.*;


/**
 * Created by adgangwa on 24-12-2016.
 * This class can be safely used, if the text to be encrypted
 * is less than 16 bytes - which is block size for 128 bit AES encryption.
 * This so, as < 16 bytes means - no possibility of block repeatition
 */
public class SimpleAES {
    // AES specification - changing will break existing encrypted streams!
    //private static final String CIPHER_SPEC = "AES/CBC/PKCS5Padding";
    private static final String CIPHER_SPEC = "AES/ECB/PKCS5Padding";

    // Key derivation specification - changing will break existing streams!
    private static final String KEYGEN_SPEC = "PBKDF2WithHmacSHA1";
    private static final int SALT_LENGTH = 10; // in bytes
    //private static final int AUTH_KEY_LENGTH = 4; // in bytes
    private static final int ITERATIONS = 1000;

    // Process input/output streams in chunks - arbitrary
    private static final int BUFFER_SIZE = 1024;


    /**
     * @return a new pseudorandom salt of the specified length
     */
    private static byte[] generateSalt(int length) {
        Random r = new SecureRandom();
        byte[] salt = new byte[length];
        r.nextBytes(salt);
        return salt;
    }

    /**
     * Derive an AES encryption key and authentication key from given password and salt,
     * using PBKDF2 key stretching. The authentication key is 64 bits long.
     *
     * @param keyLength length of the AES key in bits (128, 192, or 256)
     * @param password  the password from which to derive the keys
     * @param salt      the salt from which to derive the keys
     * @return a Keys object containing the two generated keys
     */
    private static SecretKey keygen(int keyLength, char[] password, byte[] salt) {
        SecretKeyFactory factory;
        try {
            factory = SecretKeyFactory.getInstance(KEYGEN_SPEC);
        } catch (NoSuchAlgorithmException impossible) {
            return null;
        }
        // derive a longer key, then split into AES key and authentication key
        //KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, keyLength + AUTH_KEY_LENGTH * 8);
        KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, keyLength);
        SecretKey tmp = null;
        try {
            tmp = factory.generateSecret(spec);
        } catch (InvalidKeySpecException impossible) {
        }
        byte[] fullKey = tmp.getEncoded();
        /*SecretKey authKey = new SecretKeySpec( // key for password authentication
                Arrays.copyOfRange(fullKey, 0, AUTH_KEY_LENGTH), "AES");*/
        SecretKey encKey = new SecretKeySpec( // key for AES encryption
                Arrays.copyOfRange(fullKey, 0, fullKey.length), "AES");
        //return new SimplePBAES.Keys(encKey);
        return encKey;
    }

    /**
     * Encrypts a stream of data. The encrypted stream consists of a header
     * followed by the raw AES data. The header is broken down as follows:<br/>
     * <ul>
     * <li><b>keyLength</b>: AES key length in bytes (valid for 16, 24, 32) (1 byte)</li>
     * <li><b>salt</b>: pseudorandom salt used to derive keys from password (16 bytes)</li>
     * <li><b>authentication key</b> (derived from password and salt, used to
     * check validity of password upon decryption) (8 bytes)</li>
     * <li><b>IV</b>: pseudorandom AES initialization vector (16 bytes)</li>
     * </ul>
     *
     * @param keyLength key length to use for AES encryption (must be 128, 192, or 256)
     * @param password  password to use for encryption
     * @param text     string to encrypt
     * @throws SimpleAES.InvalidKeyLengthException             if keyLength is not 128, 192, or 256
     * @throws SimpleAES.StrongEncryptionNotAvailableException if keyLength is 192 or 256, but the Java runtime's jurisdiction
     *                                                           policy files do not allow 192- or 256-bit encryption
     * @throws IOException
     */
    public static String encrypt(int keyLength, char[] password, String text)
            throws SimpleAES.InvalidKeyLengthException, SimpleAES.StrongEncryptionNotAvailableException, IOException {
        // Check validity of key length
        if (keyLength != 128 && keyLength != 192 && keyLength != 256) {
            throw new SimpleAES.InvalidKeyLengthException(keyLength);
        }

        // generate salt and derive keys for authentication and encryption
        byte[] salt = generateSalt(SALT_LENGTH);
        //SimplePBAES.Keys keys = keygen(keyLength, password, salt);
        SecretKey key = keygen(keyLength, password, salt);

        // initialize AES encryption
        Cipher encrypt = null;
        try {
            encrypt = Cipher.getInstance(CIPHER_SPEC);
            encrypt.init(Cipher.ENCRYPT_MODE, key);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException impossible) {
        } catch (InvalidKeyException e) { // 192 or 256-bit AES not available
            throw new SimpleAES.StrongEncryptionNotAvailableException(keyLength);
        }

        // get initialization vector
        /*byte[] iv = null;
        try {
            iv = encrypt.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
        } catch (InvalidParameterSpecException impossible) { }*/

        // write authentication and AES initialization data
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(keyLength / 8);
        output.write(salt);
        //output.write(keys.authentication.getEncoded());
        //output.write(iv);

        // read data from input into buffer, encrypt and write to output
        byte[] buffer = new byte[BUFFER_SIZE];
        int numRead;
        byte[] encrypted = null;
        ByteArrayInputStream input = new ByteArrayInputStream(text.getBytes());
        while ((numRead = input.read(buffer)) > 0) {
            encrypted = encrypt.update(buffer, 0, numRead);
            if (encrypted != null) {
                output.write(encrypted);
            }
        }
        try { // finish encryption - do final block
            encrypted = encrypt.doFinal();
        } catch (IllegalBlockSizeException | BadPaddingException impossible) {
        }
        if (encrypted != null) {
            output.write(encrypted);
        }

        return Base64.getEncoder().encodeToString(output.toByteArray());
    }

    /**
     * Decrypts a stream of data that was encrypted by {@link #encrypt}.
     *
     * @param password the password used to encrypt/decrypt the stream
     * @param encryptedText  encrypted string to be decrypted
     * @return the decrypted string
     * @throws SimpleAES.InvalidAESStreamException             if the given input stream is not a valid AES-encrypted stream
     * @throws SimpleAES.StrongEncryptionNotAvailableException if the stream is 192 or 256-bit encrypted, and the Java runtime's
     *                                                           jurisdiction policy files do not allow for AES-192 or 256
     * @throws IOException
     */
    public static String decrypt(char[] password, String encryptedText)
            throws SimpleAES.InvalidAESStreamException, IOException,
            SimpleAES.StrongEncryptionNotAvailableException {

        ByteArrayInputStream input = new ByteArrayInputStream(Base64.getDecoder().decode(encryptedText.getBytes()));
        //ByteArrayInputStream input = new ByteArrayInputStream(encryptedText.getBytes());
        int keyLength = input.read() * 8;
        // Check validity of key length
        if (keyLength != 128 && keyLength != 192 && keyLength != 256) {
            throw new SimpleAES.InvalidAESStreamException();
        }

        // read salt, generate keys, and authenticate password
        byte[] salt = new byte[SALT_LENGTH];
        input.read(salt);
        //SimplePBAES.Keys keys = keygen(keyLength, password, salt);
        SecretKey key = keygen(keyLength, password, salt);
        /*byte[] authRead = new byte[AUTH_KEY_LENGTH];
        input.read(authRead);
        if (!Arrays.equals(keys.authentication.getEncoded(), authRead)) {
            throw new SimplePBAES.InvalidPasswordException();
        }*/

        // initialize AES decryption
        /*byte[] iv = new byte[16]; // 16-byte I.V. regardless of key size
        input.read(iv);*/
        Cipher decrypt = null;
        try {
            decrypt = Cipher.getInstance(CIPHER_SPEC);
            decrypt.init(Cipher.DECRYPT_MODE, key);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException impossible) {
        } catch (InvalidKeyException e) { // 192 or 256-bit AES not available
            throw new SimpleAES.StrongEncryptionNotAvailableException(keyLength);
        }

        // read data from input into buffer, decrypt and write to output
        byte[] buffer = new byte[BUFFER_SIZE];
        int numRead;
        byte[] decrypted;
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        while ((numRead = input.read(buffer)) > 0) {
            decrypted = decrypt.update(buffer, 0, numRead);
            if (decrypted != null) {
                output.write(decrypted);
            }
        }
        try { // finish decryption - do final block
            decrypted = decrypt.doFinal();
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new SimpleAES.InvalidAESStreamException(e);
        }
        if (decrypted != null) {
            output.write(decrypted);
        }

        return new String(output.toByteArray(), StandardCharsets.UTF_8);

        //return keyLength;
    }

    /**
     * A tuple of encryption and authentication keys returned by {@link #keygen}
     */
    /*private static class Keys {
        public final SecretKey encryption, authentication;
        public Keys(SecretKey encryption, SecretKey authentication) {
            this.encryption = encryption;
            this.authentication = authentication;
        }
    }*/


    //******** EXCEPTIONS thrown by encrypt and decrypt ********

    /**
     * Thrown if an attempt is made to encrypt a stream with an invalid AES key length.
     */
    public static class InvalidKeyLengthException extends Exception {
        InvalidKeyLengthException(int length) {
            super("Invalid AES key length: " + length);
        }
    }

    /**
     * Thrown if 192- or 256-bit AES encryption or decryption is attempted,
     * but not available on the particular Java platform.
     */
    public static class StrongEncryptionNotAvailableException extends Exception {
        public StrongEncryptionNotAvailableException(int keySize) {
            super(keySize + "-bit AES encryption is not available on this Java platform.");
        }
    }

    /**
     * Thrown if an attempt is made to decrypt an invalid AES stream.
     */
    public static class InvalidAESStreamException extends Exception {
        public InvalidAESStreamException() {
            super();
        }

        ;

        public InvalidAESStreamException(Exception e) {
            super(e);
        }
    }
}
