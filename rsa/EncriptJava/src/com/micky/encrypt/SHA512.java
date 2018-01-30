package com.micky.encrypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA512 {

	public String hash(String data, String salt) {

		String ret = null;

		try {
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			md.update(salt.getBytes());
			byte[] b = md.digest(data.getBytes());

			StringBuffer buff = new StringBuffer();
			for (int i = 0; i < b.length; ++i) {
				buff.append(Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1));
			}
			ret = buff.toString();

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return ret;
	}

	public static void main(String[] args) {
		SHA512 sha512 = new SHA512();
		String result = sha512.hash("523456", "754");
		System.out.println(result);
	}
}
