package com.pachain.voting.service.common;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;

import javax.crypto.Cipher;
import java.io.*;
import java.lang.reflect.Field;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;

public class ECCUtils {
    static{
        Security.addProvider(new BouncyCastleProvider());
    }
    private final static int KEY_SIZE=256;
    private final static String SIGNATURE="SHA256withECDSA";
    private static Logger logger = org.slf4j.LoggerFactory.getLogger(ECCUtils.class);

    private static void printProvider(){
        Provider provider=new BouncyCastleProvider();
        for(Provider.Service service:provider.getServices()){
            System.out.println(service.getType()+":"+service.getAlgorithm());
        }
    }
    public static HashMap<String, Object> getKeys() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(KEY_SIZE, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        HashMap<String, Object> map = new HashMap<String, Object>();
        ECPublicKey publicKey=(ECPublicKey)keyPair.getPublic();
        ECPrivateKey privateKey=(ECPrivateKey)keyPair.getPrivate();
        Base64.Encoder encoder = Base64.getEncoder();
        map.put("public", publicKey);
        map.put("private", privateKey);
        return map;
    }
    private static String getSignature(File certFile) throws Exception{
        CertificateFactory certificateFactory=CertificateFactory.getInstance("X.509","BC");
        X509Certificate x509Certificate=(X509Certificate) certificateFactory.generateCertificate(new FileInputStream(certFile));
        return x509Certificate.getSigAlgName();
    }
    public static ECPublicKey getPublicKeyFromString(String pubStr) throws Exception{
        if(pubStr.startsWith("-----")){
            return  getPublicKeyFromPEMString(pubStr);
        }
        byte[] keyBytes=Base64.getDecoder().decode(pubStr);
        X509EncodedKeySpec keySpec=new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory=KeyFactory.getInstance("EC","BC");
        ECPublicKey publicKey=(ECPublicKey)keyFactory.generatePublic(keySpec);
        return publicKey;
    }
    public static ECPublicKey getPublicKeyFromPEMString(String data) throws IOException {
        final Reader pemReader = new StringReader(data);
        final SubjectPublicKeyInfo pemPair;
        try (PEMParser pemParser = new PEMParser(pemReader)) {
            pemPair = (SubjectPublicKeyInfo) pemParser.readObject();
        }
        return (ECPublicKey) new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getPublicKey(pemPair);
    }
    public static ECPrivateKey getPrivateKeyFromString(String priStr)throws Exception{
        if(priStr.startsWith("-----")){
            return  getPrivateKeyFromPEMString(priStr);
        }
        byte[] keyBytes=Base64.getDecoder().decode(priStr);
        PKCS8EncodedKeySpec keySpec=new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory=KeyFactory.getInstance("EC","BC");
        ECPrivateKey privateKey=(ECPrivateKey) keyFactory.generatePrivate(keySpec);
        return privateKey;
    }
    public static ECPrivateKey getPrivateKeyFromPEMString(String data) throws IOException {
        final Reader pemReader = new StringReader(data);
        final PrivateKeyInfo pemPair;
        try (PEMParser pemParser = new PEMParser(pemReader)) {
            pemPair = (PrivateKeyInfo) pemParser.readObject();
        }
        return (ECPrivateKey)new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getPrivateKey(pemPair);
    }
    public static ECPublicKey getPublicKeyFromX509CertificateString(String data) throws Exception {
        final Reader pemReader = new StringReader(data);
        final X509CertificateHolder holder;
        try (PEMParser pemParser = new PEMParser(pemReader)) {
            holder = (X509CertificateHolder) pemParser.readObject();
        }
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(holder.getEncoded());
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
        return (ECPublicKey)cert.getPublicKey();
    }
    public static X509Certificate getX509CertificateFromString(String data) throws Exception {
        final Reader pemReader = new StringReader(data);
        final X509CertificateHolder holder;
        try (PEMParser pemParser = new PEMParser(pemReader)) {
            holder = (X509CertificateHolder) pemParser.readObject();
        }
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(holder.getEncoded());
        return  (X509Certificate) certFactory.generateCertificate(in);
    }
    public static byte[] encrypt(byte[] content,ECPublicKey publicKey) throws Exception{
        Cipher cipher=Cipher.getInstance("ECIES","BC");
        //setFieldValueByFieldName(cipher);
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        return  cipher.doFinal(content);
    }
    public static byte[] decrypt(byte[] content,ECPrivateKey privateKey) throws Exception{
        Cipher cipher=Cipher.getInstance("ECIES","BC");
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        return cipher.doFinal(content);
    }
    private static void setFieldValueByFieldName(Cipher object){
        if(object==null){
            return;
        }
        Class cipher=object.getClass();
        try{
            Field cipherField=cipher.getDeclaredField("cryptoPerm");
            cipherField.setAccessible(true);
            Object cryptoPerm=cipherField.get(object);
            Class c=cryptoPerm.getClass();
            Field[] cs=c.getDeclaredFields();
            Field cryptoPermField=c.getDeclaredField("maxKeySize");
            cryptoPermField.setAccessible(true);
            cryptoPermField.set(cryptoPerm,257);
        }catch (Exception e){
            e.printStackTrace();
        }
    }
    public static byte[] sign(String content,ECPrivateKey privateKey) throws Exception {
        Signature signature=Signature.getInstance(SIGNATURE);
        signature.initSign(privateKey);
        signature.update(content.getBytes());
        return signature.sign();
    }
    public static boolean verify(String content,byte[] sign,ECPublicKey publicKey) throws Exception{
        Signature signature=Signature.getInstance(SIGNATURE);
        signature.initVerify(publicKey);
        signature.update(content.getBytes());
        return signature.verify(sign);
    }
}
