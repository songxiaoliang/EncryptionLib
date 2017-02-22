package com.android.song.encryptionlib;

/**
 * 异或加密：
 *   某个字符或者数值 x 与一个数值 m 进行异或运算得到 y ,
 *   则再用 y 与 m 进行异或运算就可还原为 x
 * 使用场景：
 *   1. 两个变量的互换（不借助第三个变量）
 *   2. 数据的简单加密解密
 * Created by Song on 2017/2/22.
 */
public class XORUtils {

    /**
     * 固定key方式加解密
     * @param data 原字符串
     * @param key
     * @return
     */
    public static String encrypt(String data,int key) {

        byte[] dataBytes = data.getBytes();
        int length = dataBytes.length;
        for (int i = 0; i < length; i++) {
            dataBytes[i] ^= key;
        }
        return new String(dataBytes);
    }

    /**
     * 不固定key方式加密
     * @param bytes 原字节数组
     * @return
     */
    public byte[] encrypt(byte[] bytes) {
        int len = bytes.length;
        int key = 0x12;
        for (int i = 0; i < len; i++) {
            bytes[i] = (byte) (bytes[i] ^ key);
            key = bytes[i];
        }
        return bytes;
    }

    /**
     * 不固定key方式解密
     * @param bytes 原字节数组
     * @return
     */
    public byte[] decrypt(byte[] bytes) {
        int len = bytes.length;
        int key = 0x12;
        for (int i = len - 1; i > 0; i--) {
            bytes[i] = (byte) (bytes[i] ^ bytes[i - 1]);
        }
        bytes[0] = (byte) (bytes[0] ^ key);
        return bytes;
    }
}
