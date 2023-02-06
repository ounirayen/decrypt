package com.example.demo;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public final class EncryptionUtils {

    private EncryptionUtils() {
        throw new IllegalStateException("Utility class");
    }

    public static String getEncryptionKey() {
        return "RbpV6z5XF8xRK3Nup8jBKv";
    }

    public static String getInitializationVector() {
        return "bf875ae8804d17f3a96dba9f43a5a4ee";
    }

    private static SecretKeySpec mapToSecretKeySpec() {
        return new SecretKeySpec(Base64.decodeBase64(getEncryptionKey()), "AES");
    }

    public static String encrypt(Object object) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = Base64.decodeBase64(getInitializationVector());
            final SecretKeySpec secretKey = mapToSecretKeySpec();
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(object);
            byte[] objectBytes = byteArrayOutputStream.toByteArray();
            byte[] encryptedObjectBytes = cipher.doFinal(objectBytes);
            byteArrayOutputStream.close();
            objectOutputStream.close();
            byte[] ivAndEncryptedObjectBytes = new byte[iv.length + encryptedObjectBytes.length];
            System.arraycopy(iv, 0, ivAndEncryptedObjectBytes, 0, iv.length);
            System.arraycopy(encryptedObjectBytes, 0, ivAndEncryptedObjectBytes, iv.length, encryptedObjectBytes.length);

            return Base64.encodeBase64String(ivAndEncryptedObjectBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Object decrypt(String encryptedInfo) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = Base64.decodeBase64(getInitializationVector());
            final SecretKeySpec secretKey = mapToSecretKeySpec();
            final byte[] encryptedText = Base64.decodeBase64(encryptedInfo);
            System.arraycopy(encryptedText, 0, iv, 0, 16);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
            byte[] encryptedObjectBytes = new byte[encryptedText.length - 16];
            System.arraycopy(encryptedText, 16, encryptedObjectBytes, 0, encryptedObjectBytes.length);
            byte[] objectBytes = cipher.doFinal(encryptedObjectBytes);
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(objectBytes);
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            Object object = objectInputStream.readObject();
            byteArrayInputStream.close();
            objectInputStream.close();

            return object;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}


	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);

		final Product product = new Product().id(UUID.randomUUID().toString()).name("test");
		final String data = EncryptionUtils.encrypt(product);
		System.out.println(data);

		final Product object = (Product) EncryptionUtils.decrypt(data);
		System.out.println(object.getId());
		System.out.println(object.getName());
	}
