package com.pachain.voting.service.common;


import javax.crypto.Cipher;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class RSAUtils {
    static {
            Security.addProvider(new BouncyCastleProvider());
    }
    private static Logger logger = org.slf4j.LoggerFactory.getLogger(RSAUtils.class);

    public static HashMap<String, Object> getKeys() throws NoSuchAlgorithmException, IOException {
        HashMap<String, Object> map = new HashMap<String, Object>();
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        BASE64Encoder encoder = new BASE64Encoder();
        map.put("public", publicKey);
        map.put("private", privateKey);
        return map;
    }
    public  static  RSAPrivateKey getRSAPrivateKey(String data) throws Exception {
        BASE64Decoder base64Decoder= new BASE64Decoder();
        byte[] buffer= base64Decoder.decodeBuffer(data);
        PKCS8EncodedKeySpec keySpec= new PKCS8EncodedKeySpec(buffer);
        KeyFactory keyFactory= KeyFactory.getInstance("RSA");
        return  (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }
    public static RSAPublicKey getRSAPublicKey(String data) throws Exception{
        BASE64Decoder base64Decoder= new BASE64Decoder();
        byte[] buffer= base64Decoder.decodeBuffer(data);
        KeyFactory keyFactory= KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec= new X509EncodedKeySpec(buffer);
        return  (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }
    public static RSAPublicKey getRSAPublicKeyWithPKCS8(String data) throws Exception{
        BASE64Decoder base64Decoder= new BASE64Decoder();
        byte[] buffer= base64Decoder.decodeBuffer(data);
        KeyFactory keyFactory= KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec= new PKCS8EncodedKeySpec(buffer);
        return  (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    public static String encryptByPublicKey(String data, RSAPublicKey publicKey) throws Exception {
        //RSA/ECB/NoPadding,RSA/ECB/PKCS1Padding(
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        int max_len=((publicKey.getModulus().bitLength() - 384) / 8) + 37;
        byte[] bts= data.getBytes();
        byte[] buffer=new byte[max_len];
        int blocks = (bts.length-1)/max_len+1;
        String mi = "";
        if(blocks==1){
            mi = bcd2Str(cipher.doFinal(bts));
        }
        else{
            for(int x=0;x<blocks;x++){
                if(x==blocks-1){
                    buffer=new byte[bts.length-x*max_len];
                }
                System.arraycopy(bts, x*max_len, buffer, 0,buffer.length);
                mi += bcd2Str(cipher.doFinal(buffer));
            }
        }
        return mi;
    }
    public static byte[] encryptByPublicKeyForBytes(String data, RSAPublicKey publicKey) throws Exception {
        //RSA/ECB/NoPadding,RSA/ECB/PKCS1Padding(
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        int max_len=((publicKey.getModulus().bitLength() - 384) / 8) + 37;
        byte[] bts= data.getBytes();
        byte[] buffer=new byte[max_len];
        int blocks = (bts.length-1)/max_len+1;
        byte[] mi=new byte[0];
        if(blocks==1){
            mi = cipher.doFinal(bts);
        }
        else{
            for(int x=0;x<blocks;x++){
                if(x==blocks-1){
                    buffer=new byte[bts.length-x*max_len];
                }
                System.arraycopy(bts, x*max_len, buffer, 0,buffer.length);
                byte[] bytes = cipher.doFinal(buffer);
                mi=byteMerger(mi,bytes);
            }
        }
        return mi;
    }
    public static String encryptByPrivateKey(String data, RSAPrivateKey privateKey)throws Exception {
        //RSA/ECB/NoPadding,RSA/ECB/PKCS1Padding(
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        int max_len=((privateKey.getModulus().bitLength() - 384) / 8) + 37;
        byte[] bts= data.getBytes();
        byte[] buffer=new byte[max_len];
        int blocks = (bts.length-1)/max_len+1;
        String mi = "";
        if(blocks==1){
            mi = bcd2Str(cipher.doFinal(bts));
        }
        else{
            for(int x=0;x<blocks;x++){
                if(x==blocks-1){
                    buffer=new byte[bts.length-x*max_len];
                }
                System.arraycopy(bts, x*max_len, buffer, 0,buffer.length);
                mi += bcd2Str(cipher.doFinal(buffer));
            }
        }
        return mi;
    }
    public static String decryptByPrivateKeyyForBytes(String data, RSAPrivateKey privateKey) throws Exception {
        //RSA/ECB/NoPadding,RSA/ECB/PKCS1Padding(
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        int key_len = privateKey.getModulus().bitLength() / 8;
        byte[] bytes = Base64.getDecoder().decode(data);
        String ming = "";
        byte[][] arrays = splitArray(bytes, key_len);
        for(byte[] arr : arrays) {
            ming += new String(cipher.doFinal(arr), "UTF-8");
        }
        return ming;
    }
    public static String decryptByPrivateKey(String data, RSAPrivateKey privateKey) throws Exception {
        //RSA/ECB/NoPadding,RSA/ECB/PKCS1Padding(
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        int key_len = privateKey.getModulus().bitLength() / 8;
        byte[] bytes = bcd2Str(Base64.getDecoder().decode(data)).getBytes();
        byte[] bcd = ASCII_To_BCD(bytes, bytes.length);
        String ming = "";
        byte[][] arrays = splitArray(bcd, key_len);
        for(byte[] arr : arrays) {
            ming += new String(cipher.doFinal(arr), "UTF-8");
        }
        return ming;
    }
    public static String decryptByPublicKey(String data, RSAPublicKey publicKey) throws Exception {
        //RSA/ECB/NoPadding,RSA/ECB/PKCS1Padding(
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        int key_len = publicKey.getModulus().bitLength() / 8;
        byte[] bytes = bcd2Str(Base64.getDecoder().decode(data)).getBytes();
        byte[] bcd = ASCII_To_BCD(bytes, bytes.length);
        String ming = "";
        byte[][] arrays = splitArray(bcd, key_len);
        for(byte[] arr : arrays) {
            ming += new String(cipher.doFinal(arr), "UTF-8");
        }
        return ming;
    }
    public static byte[] sign(String content,RSAPrivateKey privateKey) throws Exception {
        Signature signature=Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(content.getBytes());
        return signature.sign();
    }
    public static boolean verify(String content, byte[] sign, RSAPublicKey publicKey) throws Exception{
        Signature signature=Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(content.getBytes());
        return signature.verify(sign);
    }
    public static byte[] ASCII_To_BCD(byte[] ascii, int asc_len) {
        byte[] bcd = new byte[asc_len / 2];
        int j = 0;
        for (int i = 0; i < (asc_len + 1) / 2; i++) {
            bcd[i] = asc_to_bcd(ascii[j++]);
            bcd[i] = (byte) (((j >= asc_len) ? 0x00 : asc_to_bcd(ascii[j++])) + (bcd[i] << 4));
        }
        return bcd;
    }
    public static byte asc_to_bcd(byte asc) {
        byte bcd;

        if ((asc >= '0') && (asc <= '9'))
            bcd = (byte) (asc - '0');
        else if ((asc >= 'A') && (asc <= 'F'))
            bcd = (byte) (asc - 'A' + 10);
        else if ((asc >= 'a') && (asc <= 'f'))
            bcd = (byte) (asc - 'a' + 10);
        else
            bcd = (byte) (asc - 48);
        return bcd;
    }
    public static String bcd2Str(byte[] bytes) {
        char temp[] = new char[bytes.length * 2], val;

        for (int i = 0; i < bytes.length; i++) {
            val = (char) (((bytes[i] & 0xf0) >> 4) & 0x0f);
            temp[i * 2] = (char) (val > 9 ? val + 'A' - 10 : val + '0');

            val = (char) (bytes[i] & 0x0f);
            temp[i * 2 + 1] = (char) (val > 9 ? val + 'A' - 10 : val + '0');
        }
        return new String(temp);
    }
    public static String[] splitString(String string, int len) {
        int x = string.length() / len;
        int y = string.length() % len;
        int z = 0;
        if (y != 0) {
            z = 1;
        }
        String[] strings = new String[x + z];
        String str = "";
        for (int i=0; i<x+z; i++) {
            if (i==x+z-1 && y!=0) {
                str = string.substring(i*len, i*len+y);
            }else{
                str = string.substring(i*len, i*len+len);
            }
            strings[i] = str;
        }
        return strings;
    }
    public static byte[][] splitArray(byte[] data,int len){
        int x = data.length / len;
        int y = data.length % len;
        int z = 0;
        if(y!=0){
            z = 1;
        }
        byte[][] arrays = new byte[x+z][];
        byte[] arr;
        for(int i=0; i<x+z; i++){
            arr = new byte[len];
            if(i==x+z-1 && y!=0){
                System.arraycopy(data, i*len, arr, 0, y);
            }else{
                System.arraycopy(data, i*len, arr, 0, len);
            }
            arrays[i] = arr;
        }
        return arrays;
    }
    public static byte[] hexStringToByte(String hex) {
        int len = (hex.length() / 2);
        byte[] result = new byte[len];
        char[] achar = hex.toCharArray();
        for (int i = 0; i < len; i++) {
            int pos = i * 2;
            result[i] = (byte)(toByte(achar[pos]) << 4 | toByte(achar[pos + 1]));
        }
        return result;
    }
    private static byte toByte(char c) {
        byte b = (byte) "0123456789ABCDEF".indexOf(c);
        return b;
    }
    public static byte[] byteMerger(byte[] bt1, byte[] bt2){
        byte[] bt3 = new byte[bt1.length+bt2.length];
        System.arraycopy(bt1, 0, bt3, 0, bt1.length);
        System.arraycopy(bt2, 0, bt3, bt1.length, bt2.length);
        return bt3;
    }
}
