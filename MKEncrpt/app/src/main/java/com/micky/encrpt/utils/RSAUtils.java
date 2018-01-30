package com.micky.encrpt.utils;


import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.apaches.commons.codec.binary.Base64;


public class RSAUtils {

	/**
	 * 非对称加密密钥算法
	 */
	public static final String KEY_ALGORITHM = "RSA";

	/**
	 * RSA密钥长度 默认1024位， 密钥长度必须是64的倍数， 范围在512至65536位之间。
	 */
	private static final int KEY_SIZE = 1024;

	/**公钥字符串*/
	private String publicKey;

	/**私钥字符串*/
	private String privateKey;

	/**
	 * 私钥解密
	 *
	 * @param data
	 *            待解密数据
	 * @param key
	 *            私钥
	 * @return byte[] 解密数据
	 * @throws Exception
	 */
	public byte[] decryptByPrivateKey(byte[] data, byte[] key) throws Exception {
		// 取得私钥
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(key);

		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// 生成私钥
		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

		// 对数据解密
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		return cipher.doFinal(data);
	}

	/**
	 *  私钥解密
	 * @param data 待解密数据
	 * @param key 私钥
	 * @return
	 * @throws Exception
	 */
	public String decryptByPrivateKey(String data, String key) throws Exception {
		byte[] bytes = decryptByPrivateKey(Base64.decodeBase64(data), Base64.decodeBase64(key));
		return new String(bytes);
	}

	/**
	 * 公钥解密
	 *
	 * @param data
	 *            待解密数据
	 * @param key
	 *            公钥
	 * @return byte[] 解密数据
	 * @throws Exception
	 */
	public byte[] decryptByPublicKey(byte[] data, byte[] key) throws Exception {

		// 取得公钥
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(key);

		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// 生成公钥
		PublicKey publicKey = keyFactory.generatePublic(pkcs8EncodedKeySpec);

		// 对数据解密
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		cipher.init(Cipher.DECRYPT_MODE, publicKey);

		return cipher.doFinal(data);
	}

	/**
	 *  公钥解密
	 * @param data 待解密数据
	 * @param key 公钥
	 * @return
	 * @throws Exception
	 */
	public String decryptByPublicKey(String data, String key) throws Exception {
		byte[] bytes = decryptByPrivateKey(Base64.decodeBase64(data), Base64.decodeBase64(key));
		return new String(bytes);
	}

	/**
	 * 公钥加密
	 *
	 * @param data
	 *            待加密数据
	 * @param key
	 *            公钥
	 * @return byte[] 加密数据
	 * @throws Exception
	 */
	public byte[] encryptByPublicKey(byte[] data, byte[] key) throws Exception {
		// 取得公钥
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key);

		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

		// 对数据加密
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		return cipher.doFinal(data);
	}

	/**
	 * 公钥加密
	 * @param data 待加密数据
	 * @param key 公钥
	 * @return
	 * @throws Exception
	 */
	public String encryptByPublicKey(String data, String key) throws Exception {
		byte[] bytes = encryptByPublicKey(data.getBytes(), Base64.decodeBase64(key));
		return Base64.encodeBase64String(bytes);
	}


	/**
	 * 私钥加密
	 *
	 * @param data
	 *            待加密数据
	 * @param key
	 *            私钥
	 * @return byte[] 加密数据
	 * @throws Exception
	 */
	public byte[] encryptByPrivateKey(byte[] data, byte[] key) throws Exception {
		// 取得私钥
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(key);

		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// 生成私钥
		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

		// 对数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());

		cipher.init(Cipher.ENCRYPT_MODE, privateKey);

		return cipher.doFinal(data);
	}

	/**
	 * 公钥加密
	 * @param data 待加密数据
	 * @param key 私钥
	 * @return
	 * @throws Exception
	 */
	public String encryptByPrivateKey(String data, String key) throws Exception {
		byte[] bytes = encryptByPrivateKey(data.getBytes(), Base64.decodeBase64(key));
		return Base64.encodeBase64String(bytes);
	}

	/**
	 * 初始化密钥
	 *
	 * @return Map 密钥Map
	 * @throws Exception
	 */
	public void generateKey() throws Exception {
		// 实例化密钥对生成器
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);

		// 初始化密钥对生成器
		keyPairGen.initialize(KEY_SIZE,new SecureRandom());

		// 生成密钥对
		KeyPair keyPair = keyPairGen.generateKeyPair();

		// 公钥
		RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();

		// 私钥
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

		publicKey = Base64.encodeBase64String(rsaPublicKey.getEncoded());
		privateKey = Base64.encodeBase64String(rsaPrivateKey.getEncoded());
	}

	public void setPrivateKey(String key) {
		this.privateKey = key;
	}

	public void setPublicKey(String key) {
		this.publicKey = key;
	}

	public String getPrivateKey() {
		return privateKey;
	}

	public String getPublicKey() {
		return publicKey;
	}

}
