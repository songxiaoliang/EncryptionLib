package com.android.song.encryptionlib;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA-512加密，不可逆
 * Created by Song on 2017/2/22.
 */

public class SHAUtils {

    private SHAUtils() {
        throw new UnsupportedOperationException("constrontor cannot be init");
    }

    /**
     * 加密
     * @param data 原字符串
     * @return 加密后新字符串
     */
    public static String encrypt(String data) {

        byte[] dataBytes = data.getBytes();
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("SHA-512");
            md5.update(dataBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] resultBytes = md5.digest();

        StringBuilder sb = new StringBuilder();
        for (byte b : resultBytes) {
            if(Integer.toHexString(0xFF & b).length() == 1) {
                sb.append("0").append(Integer.toHexString(0xFF & b));
            } else {
                sb.append(Integer.toHexString(0xFF & b));
            }
        }

        return sb.toString();
    }
}
