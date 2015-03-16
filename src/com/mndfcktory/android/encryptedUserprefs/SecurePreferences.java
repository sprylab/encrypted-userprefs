package com.mndfcktory.android.encryptedUserprefs;/*
Copyright (C) 2012 Sveinung Kval Bakken, sveinung.bakken@gmail.com

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 */

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Debug;
import android.util.Base64;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


public class SecurePreferences {

    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String KEY_TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final String SECRET_KEY_HASH_TRANSFORMATION = "SHA-256";
    private static final String CHARSET = "UTF-8";
    public static final int KEY_LENGTH_128 = 128;
    public static final int KEY_LENGTH_256 = 256;

    private final boolean encryptKeys;
    private final Cipher writer;
    private final Cipher reader;
    private final Cipher keyWriter;
    private final SharedPreferences preferences;
    private final int keyLength;
    private Context mContext;

    /**
     * This will initialize an instance of the SecurePreferences class
     *
     * @param context        your current context.
     * @param preferenceName name of preferences file (preferenceName.xml)
     * @param secureKey      the key used for encryption, finding a good key scheme is hard.
     *                       Hardcoding your key in the application is bad, but better than plaintext preferences. Having the user enter the key upon application launch is a safe(r) alternative, but annoying to the user.
     * @param salt           The salt String to use for salting the key. Should be randomly generated and
     *                       saved. Needs to be the same as the encryption key salt to be able to decrypt
     *                       the values.
     * @param encryptKeys    settings this to false will only encrypt the values,
     *                       true will encrypt both values and keys. Keys can contain a lot of information about
     *                       the plaintext value of the value which can be used to decipher the value.
     * @throws SecurePreferencesException
     */
    public SecurePreferences(Context context, String preferenceName, String secureKey, String salt,
                             boolean encryptKeys) throws SecurePreferencesException {
        this(context, preferenceName, secureKey, salt, encryptKeys, KEY_LENGTH_256);
    }

    public SecurePreferences(Context context, String preferenceName, String secureKey, String salt,
                             boolean encryptKeys, int keyLength) throws SecurePreferencesException {
        try {
            this.mContext = context;
            this.writer = Cipher.getInstance(TRANSFORMATION);
            this.reader = Cipher.getInstance(TRANSFORMATION);
            this.keyWriter = Cipher.getInstance(KEY_TRANSFORMATION);
            this.keyLength = keyLength;

            initCiphers(secureKey, salt);

            this.preferences = context.getSharedPreferences(preferenceName, Context.MODE_PRIVATE);

            this.encryptKeys = encryptKeys;
        } catch (GeneralSecurityException e) {
            throw new SecurePreferencesException(e);
        } catch (UnsupportedEncodingException e) {
            throw new SecurePreferencesException(e);
        }
    }

    private static byte[] convert(Cipher cipher, byte[] bs) throws SecurePreferencesException {
        try {
            return cipher.doFinal(bs);
        } catch (Exception e) {
            throw new SecurePreferencesException(e);
        }
    }

    /**
     * Generate a pseudo random String with SecureRandom
     *
     * @return pseudo random String
     */
    public static String getRandomString() {
        return new BigInteger(130, new SecureRandom()).toString(32);
    }

    /**
     * Generates from passphrase and salt a SecretKey with 256bit length and 1000 iterations using
     * the PBKDF2WithHmacSHA1 algorithm
     *
     * @param passphrase passphrase to use
     * @param salt       the salt to use
     * @return the generated SecretKey object
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static SecretKey generateKey(char[] passphrase, byte[] salt) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        return generateKey(passphrase, salt, KEY_LENGTH_256);
    }

    public static SecretKey generateKey(char[] passphrase, byte[] salt, int keyLength) throws NoSuchAlgorithmException,
        InvalidKeySpecException {
        // Number of PBKDF2 rounds
        final int iterations = 1000;
        if (keyLength != KEY_LENGTH_128 && keyLength != KEY_LENGTH_256) {
            throw new InvalidKeySpecException("keylength should be 128 or 256 bit long");
        }
        // Create SecretKeyFactory an generate a new SecretKey with PBKDF2WithHmacSHA1
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec keySpec = new PBEKeySpec(passphrase, salt, iterations, keyLength);

        return secretKeyFactory.generateSecret(keySpec);
    }

    /*
     * Read initialization vector from file in app private directory
     */
    private static byte[] readIvFile(File ivFile) throws IOException {
        RandomAccessFile f = new RandomAccessFile(ivFile, "r");
        byte[] bytes = new byte[(int) f.length()];
        f.readFully(bytes);
        f.close();
        return bytes;
    }

    /*
     * Write initialization vector to file in app private directory
     */
    private static void writeIvFile(File ivFile) throws IOException {
        FileOutputStream out = new FileOutputStream(ivFile);
        String id = getRandomString();
        out.write(id.getBytes());
        out.close();
    }

    /**
     * Initializes the Ciphers of this Class. Uses the supplied SecureKey and salt.
     *
     * @param secureKey Private encryption key String
     * @param salt      Random salt String. You need to use the same salt String as used for
     *                  encryption to be able to decrypt the values.
     * @throws UnsupportedEncodingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeySpecException
     */
    protected void initCiphers(String secureKey, String salt) throws UnsupportedEncodingException,
            NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException, InvalidKeySpecException {

        // Get the initialization vector
        IvParameterSpec ivSpec = getIv();

        // Generate a salted SecretKey for creating a new SecretKeySpec
        SecretKey key = generateKey(secureKey.toCharArray(), createKeyBytes(salt), keyLength);
        SecretKeySpec secretKey = createSecretKeySpec(key.getEncoded(), TRANSFORMATION);

        writer.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        reader.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        keyWriter.init(Cipher.ENCRYPT_MODE, secretKey);
    }

    protected SecretKeySpec createSecretKeySpec(final byte[] keyData, final String algorithmName) {
        return new SecretKeySpec(keyData, algorithmName);
    }

    /**
     * Generates an initialization vector and saves it to a file in the private app directory. If
     * an IV was generated previously it's loaded from the file.
     *
     * @return an IvParamterSpec object with generated IV
     */
    protected IvParameterSpec getIv() {
        File iniVec = new File(mContext.getFilesDir(), "IV");
        byte[] savesIv;
        try {
            if (!iniVec.exists())
                writeIvFile(iniVec);
            savesIv = readIvFile(iniVec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        byte[] iv = new byte[writer.getBlockSize()];
        System.arraycopy(savesIv, 0, iv, 0, writer.getBlockSize());

        return new IvParameterSpec(iv);
    }

    protected SecretKeySpec getSecretKey(String key) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        byte[] keyBytes = createKeyBytes(key);
        return new SecretKeySpec(keyBytes, TRANSFORMATION);
    }

    protected byte[] createKeyBytes(String key) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(SECRET_KEY_HASH_TRANSFORMATION);
        md.reset();
        byte[] keyBytes = md.digest(key.getBytes(CHARSET));
        return keyBytes;
    }

    /**
     * Saves the encrypted String value to the SharedPreferences. If the encryptKeys flag is set,
     * the key will be encrypted as well.
     *
     * @param key   the key of this preference, encrypted if the encryptKeys flag is set
     * @param value the preference value to be encrypted and saved
     */
    public void putString(String key, String value) {
        putValue(toKey(key), value);
    }

    public void putInt(final String key, int value) {
        putValue(toKey(key), String.valueOf(value));
    }

    public void putFloat(final String key, final float value) {
        putValue(toKey(key), String.valueOf(value));
    }

    public void putLong(final String key, final long value) {
        putValue(toKey(key), String.valueOf(value));
    }

    public void putStringSet(final String key, final Set<String> values) {
        putValueSet(toKey(key), values);
    }



    public void remove(final String key) {
        preferences.edit().remove(toKey(key)).commit();
    }

    /**
     * Reads the encrypted value from the SharedPrefs, decrypts it and returns the unencrypted
     * String value.
     *
     * @param key the key of the value to read
     * @return the unencrypted value String
     * @throws SecurePreferencesException
     */
    public String getString(String key) throws SecurePreferencesException {
        return getString(key, null);
    }

    public String getString(String key, String defaultValue) {
        if (preferences.contains(toKey(key))) {
            final String securedEncodedValue = preferences.getString(toKey(key), "");
            return decrypt(securedEncodedValue);
        }
        return defaultValue;
    }

    /**
     * Saves the boolean value to the SharedPrefs, if the encryptKeys flag is set,
     * the key will be encrypted prior saving.
     *
     * @param key   the key of the value to save
     * @param value the boolean value to save
     */
    public void putBoolean(String key, boolean value) {
        preferences.edit().putBoolean(toKey(key), value).commit();
    }

    /**
     * Returns the boolean value identified by the key. If the SharedPrefs don't contain the
     * specified key, de default value will be returned instead.
     *
     * @param key          the key for the value to save, encrypted when the encryptKeys flag is set
     * @param defaultValue the value to return if the SharedPrefs don't contain the key
     * @return the value corresponding to the key or the default value
     */
    public boolean getBoolean(String key, boolean defaultValue) {
        if (preferences.contains(toKey(key))) {
            return preferences.getBoolean(toKey(key), defaultValue);
        }
        return defaultValue;
    }

    public boolean containsKey(String key) {
        return preferences.contains(toKey(key));
    }

    public void removeValue(String key) {
        preferences.edit().remove(toKey(key)).commit();
    }

    public void clear() {
        preferences.edit().clear().commit();
    }

    private String toKey(String key) {
        if (encryptKeys)
            return encrypt(key, keyWriter);
        else return key;
    }

    private void putValue(String key, String value) throws SecurePreferencesException {
        String secureValueEncoded = encrypt(value, writer);

        preferences.edit().putString(key, secureValueEncoded).commit();
    }

    private void putValueSet(final String key, final Set<String> value) {
        Set<String> encryptedSet = new HashSet<String>();
        for (String val : value) {
            encryptedSet.add(encrypt(val, keyWriter));
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.GINGERBREAD_MR1) {
            preferences.edit().putStringSet(key, encryptedSet).commit();
        }
    }

    protected String encrypt(String value, Cipher writer) throws SecurePreferencesException {
        byte[] secureValue;
        try {
            secureValue = convert(writer, value.getBytes(CHARSET));
        } catch (UnsupportedEncodingException e) {
            throw new SecurePreferencesException(e);
        }
        String secureValueEncoded = Base64.encodeToString(secureValue, Base64.NO_WRAP);
        return secureValueEncoded;
    }

    protected String decrypt(String securedEncodedValue) {
        byte[] securedValue = Base64.decode(securedEncodedValue, Base64.NO_WRAP);
        byte[] value = convert(reader, securedValue);
        try {
            return new String(value, CHARSET);
        } catch (UnsupportedEncodingException e) {
            throw new SecurePreferencesException(e);
        }
    }

    public int getInt(final String key, final int defaultValue) {
        return Integer.valueOf(getString(key, String.valueOf(defaultValue)));
    }

    public static class SecurePreferencesException extends RuntimeException {

        public SecurePreferencesException(Throwable e) {
            super(e);
        }

    }
}
