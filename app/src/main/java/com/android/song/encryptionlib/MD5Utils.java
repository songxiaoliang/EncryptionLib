package com.android.song.encryptionlib;

import android.text.TextUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * MD5加密工具类，不可逆
 * Created by Song on 2017/2/22.
 */

public class MD5Utils {

    private MD5Utils() {
        throw new UnsupportedOperationException("constrontor cannot be init");
    }

    /**
     * 字符串加密
     * @param data 原字符串
     * @return 加密后新字符串
     */
    public static String encryptStr(String data) {

        byte[] dataBytes = data.getBytes();
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
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

    /**
     * 文件加密
     * @param filePath 文件路径
     * @return 加密后的字符串
     */
    public static String encryptFile(String filePath) {

        String result = "";
        FileInputStream fis = null;
        File file = new File(filePath);
        StringBuilder sb = new StringBuilder();
        try {
            fis = new FileInputStream(file);
            MappedByteBuffer byteBuffer = fis.getChannel().map(FileChannel.MapMode.READ_ONLY,0,file.length());
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(byteBuffer);
            byte[] resultBytes = md5.digest();

            for (byte b : resultBytes) {
                if(Integer.toHexString(0xFF & b).length() == 1) {
                    sb.append("0").append(Integer.toHexString(0xFF & b));
                } else {
                    sb.append(Integer.toHexString(0xFF & b));
                }
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return sb.toString();
    }


    /**
     * 跑字典，以穷举法来破解MD5的加密，为了加大破解难度，可以采用以下方式
     */


    /**
     * 多次MD5加密
     * @param data
     * @param time 重复加密次数
     * @return
     */
    public static String repeatEncrypt(String data,int time) {

        if(TextUtils.isEmpty(data)) {
            return "";
        }

        String result = encryptStr(data);
        for (int i = 0; i < time - 1; i++) {
            result = encryptStr(result);
        }
        return encryptStr(result);
    }

    /**
     * MD5加盐
     *
     * 方式：
     *  1. string + key(盐值) 然后MD5加密
     *  2. 用string明文的hashcode作为盐，然后MD5加密
     *  3. 随机生成一串字符串作为盐值，然后MD5加密
     *
     * 该方法采用 string + key
     * @param data
     * @param salt
     * @return
     */
    public static String encryptSalt(String data, String salt) {

        if(TextUtils.isEmpty(data)) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] resultBytes = md5.digest((data + salt).getBytes());
            for (byte b : resultBytes) {
                if(Integer.toHexString(0xFF & b).length() == 1) {
                    sb.append("0").append(Integer.toHexString(0xFF & b));
                } else {
                    sb.append(Integer.toHexString(0xFF & b));
                }
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return sb.toString();
    }
}
