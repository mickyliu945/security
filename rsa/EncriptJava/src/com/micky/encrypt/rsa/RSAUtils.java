package com.micky.encrypt.rsa;


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

import org.apache.commons.codec.binary.Base64;


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
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(key);

		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// 生成私钥
		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

		// 对数据解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());

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
	public String decryptByPrivateKey(String data) throws Exception {
		byte[] bytes = decryptByPrivateKey(Base64.decodeBase64(data), Base64.decodeBase64(privateKey));
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
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(key);

		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// 生成公钥
		PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);

		// 对数据解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());

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
	public String decryptByPublicKey(String data) throws Exception {
		byte[] bytes = decryptByPrivateKey(Base64.decodeBase64(data), Base64.decodeBase64(publicKey));
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
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(key);

		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);

		// 对数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());

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
	public String encryptByPublicKey(String data) throws Exception {
		byte[] bytes = encryptByPublicKey(data.getBytes(), Base64.decodeBase64(publicKey));
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
	public String encryptByPrivateKey(String data) throws Exception {
		byte[] bytes = encryptByPrivateKey(data.getBytes(), Base64.decodeBase64(privateKey));
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
	
	public static void main(String[] args) throws Exception {
//		long begin = System.currentTimeMillis();
//		RSAUtils rsaUtils = new RSAUtils();
//		rsaUtils.generateKey();
//		System.out.println(rsaUtils.getPrivateKey());
//		System.out.println(rsaUtils.getPublicKey());
//		String encryptStr = rsaUtils.encryptByPublicKey("DDDDafda#$@@$", rsaUtils.getPublicKey());
//		System.out.println(encryptStr);
//		String decriptStr = rsaUtils.decryptByPrivateKey(encryptStr, rsaUtils.getPrivateKey());
//		System.out.println(decriptStr);
//		
//		for (int i = 0; i < 1000; i++) {
//			encryptStr = rsaUtils.encryptByPublicKey("DDDDafda#$@@$", rsaUtils.getPublicKey());
//			decriptStr = rsaUtils.decryptByPrivateKey(encryptStr, rsaUtils.getPrivateKey());
//		}
//		
//		System.out.println((System.currentTimeMillis() - begin));
		
		long begin = System.currentTimeMillis();
		RSAUtils rsaUtils = new RSAUtils();
		  rsaUtils.setPrivateKey("MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJQnZtjICoMCwzcZnif3t0fW4hyLqaOGLVfEX/6tQa+wCJq6LI9B7SnCzITsuX3YbkmIo96znWBbL7o7XF/p190TSulFDYyWNnNmvqC8L/0ZzARuRBEepF8IIFtlH013R34WBTsRl0FOr5WAwqFSe4crMCi3ktCuQdM7xGnIZCzVAgMBAAECgYA9uLiRIa23bOQ1RVftYLcbl7s1lz3CIXkscmRnrniKH/VFuMAtopKSblRUIGcatZskyWcztXKgHP0iQe63Cq3iCn1qYpVEp3QBONAoO+qrkL80XndYOuG1El8nIvg7bvR2DChkzWSfZq5OOfE5bxmva3xyhgvBnhSH10+ZI32QgQJBANOp0Z/Jb5coumT/mVpcT+/MsqxxhYYsCu3Y2u5lT2+wl78XDzz2sGnjeGfIXjXwqUl3x6pVWZ2Ry0Tzbnd1KGECQQCzL/gOlV2evm5C0FsQhrYpTj9kYZ7XydsEU87d7XRuaRZb5UhruL1rMwmog7bu8dAsCacFqVUuULGtB8qFcYj1AkEAuMRAGgTkZYaHF41L1+ZHXWRKAGBkl5gwvimUC5Dig/QasxO1GJmbrAOGYso0+08m59worpcs0HCpiXoazyq1YQJAba1k1fhS74F8F+VUeA8cnLfKUXT3NvnU1xc9PdXEOHiWOPVkmJrhRiZdOQo2BJd6ZhoaY3q8Krc1qcVlDrzpqQJBAJwEs0iJRc6uYnUu7LmxxReKdgOH4oDXURPaIRd55GGWihcT+x59vSqQo6/QUpk/wFvNY35RwsQ6Vuttx6KtYyQ=");
          rsaUtils.setPublicKey("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCUJ2bYyAqDAsM3GZ4n97dH1uIci6mjhi1XxF/+rUGvsAiauiyPQe0pwsyE7Ll92G5JiKPes51gWy+6O1xf6dfdE0rpRQ2MljZzZr6gvC/9GcwEbkQRHqRfCCBbZR9Nd0d+FgU7EZdBTq+VgMKhUnuHKzAot5LQrkHTO8RpyGQs1QIDAQAB");
          String encryptStr = rsaUtils.encryptByPublicKey("DDDDafda#$@@$");
          System.out.println(encryptStr);
          encryptStr = "P6UZ3z9kFiza1XksFNFxqMeM5cAGp0vY5FkucxAwikO27yOGH05PttS3i3iwFKj41CpXuKwij4ghhporLplh9rll1xxI10oKL5SspV8iqOTiC5yAB0/cI/4hhZFjc8AQvTtp+06jyGZpQm6RG1QxIHAZeTw102qHeJVQlkGl3Fg=";
          String decriptStr = rsaUtils.decryptByPrivateKey(encryptStr);
          System.out.println(decriptStr);
		System.out.println((System.currentTimeMillis() - begin));
		
	}
	
}
