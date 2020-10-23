package com.pachain.voting.service.common;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.pachain.voting.service.fabric.WalletClient;
import org.hyperledger.fabric.gateway.Identity;
import org.slf4j.Logger;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Part;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class GlobalUtils {
    private static Logger logger = org.slf4j.LoggerFactory.getLogger(GlobalUtils.class);
    private static String __rsaPublicKey=null;
    private static String __eccPublicKey=null;
    private static RSAPrivateKey __rsaPrivateKey=null;
    private static ECPrivateKey __eccPrivateKey=null;
    private static Lock __keysLock= new ReentrantLock();
    public static ConfigurableApplicationContext applicationContext=null;

    public static void setApplicationContext(ConfigurableApplicationContext content){
        if(applicationContext==null){
            applicationContext=content;
        }
    }
    public static <T> T GetBean(String beanName){
        return (T) applicationContext.getBean(beanName);
    }
    private static void  __initKeys(){
        __keysLock.lock();
        try{
            Identity admin = WalletClient.GetUserIdentity("admin");
            if(admin==null){
                WalletClient.EnrollAdmin();
            }
            Base64.Encoder encoder = Base64.getEncoder();
            if(__rsaPrivateKey==null){
                File f=new File("wallet/rsa.public");
                if(!f.exists()){
                    HashMap<String, Object> keys = RSAUtils.getKeys();
                    __rsaPublicKey = encoder.encodeToString(((RSAPublicKey)keys.get("public")).getEncoded());
                    __rsaPrivateKey = (RSAPrivateKey) keys.get("private");
                    BufferedWriter bw = new BufferedWriter(new FileWriter(f,false));
                    bw.write(__rsaPublicKey);
                    bw.close();
                    bw = new BufferedWriter(new FileWriter(new File("wallet/rsa.private"),false));
                    bw.write(encoder.encodeToString(__rsaPrivateKey.getEncoded()));
                    bw.close();
                }
                else{
                    __rsaPublicKey=readFileContent(f);
                    __rsaPrivateKey=RSAUtils.getRSAPrivateKey(readFileContent(new File("wallet/rsa.private")));
                }
            }
            if(__eccPrivateKey==null){
                File f=new File("wallet/ecc.public");
                if(!f.exists()){
                    HashMap<String, Object> keys = ECCUtils.getKeys();
                    __eccPublicKey = encoder.encodeToString(((ECPublicKey)keys.get("public")).getEncoded());
                    __eccPrivateKey = (ECPrivateKey) keys.get("private");
                    BufferedWriter bw = new BufferedWriter(new FileWriter(f,false));
                    bw.write(__eccPublicKey);
                    bw.close();
                    bw = new BufferedWriter(new FileWriter(new File("wallet/ecc.private"),false));
                    bw.write(encoder.encodeToString(__eccPrivateKey.getEncoded()));
                    bw.close();
                }
                else{
                    __eccPublicKey=readFileContent(f);
                    __eccPrivateKey=ECCUtils.getPrivateKeyFromString(readFileContent(new File("wallet/ecc.private")));
                }
            }
        }catch(Exception ex){}
        finally {
            __keysLock.unlock();
        }
    }
    public static boolean verifySignature(String keyType, String publicKey, String data, String signature){
        boolean keyChecked=false;
        try{
            if(keyType.toLowerCase().equals("rsa")){
                RSAPublicKey pKey = RSAUtils.getRSAPublicKey(publicKey);
                keyChecked= RSAUtils.verify(data, Base64.getDecoder().decode(signature),pKey);
            }else{
                ECPublicKey pKey = ECCUtils.getPublicKeyFromString(publicKey);
                keyChecked= ECCUtils.verify(data, Base64.getDecoder().decode(signature),pKey);
            }
        }catch (Exception ex){
            logger.error(ex.getMessage()+"\n"+ex.getStackTrace());
        }
        return keyChecked;
    }
    public static String encryptData(String keyType, String publicKey, String data) throws Exception {
        if(keyType.toLowerCase().equals("rsa")) {
            return Base64.getEncoder().encodeToString(RSAUtils.encryptByPublicKeyForBytes(data, RSAUtils.getRSAPublicKey(publicKey)));
        }else {
            return Base64.getEncoder().encodeToString(ECCUtils.encrypt(data.getBytes(StandardCharsets.UTF_8), ECCUtils.getPublicKeyFromString(publicKey)));
        }
    }

    public static String decryptData(ECPrivateKey privateKey, String data) throws Exception {
        return new String(ECCUtils.decrypt(Base64.getDecoder().decode(data), privateKey));
    }

    public static String GetRSAPublicKey() {
        __initKeys();
        return __rsaPublicKey;
    }
    public static RSAPrivateKey GetRSAPrivateKey() throws Exception {
        __initKeys();
        return __rsaPrivateKey;
    }
    public static String GetECCPublicKey() {
        __initKeys();
        return __eccPublicKey;
    }
    public static ECPrivateKey GetECCPrivateKey() throws Exception {
        __initKeys();
        return __eccPrivateKey;
    }

    public static String readFileContent(File f) throws IOException {
        FileInputStream inputStream = new FileInputStream(f);
        BufferedReader br=new BufferedReader(new InputStreamReader(inputStream));
        String js="";
        String s="";
        while((s=br.readLine())!=null)
            js=js+s;
        br.close();
        inputStream.close();
        return js;
    }
    public static RequestParams getParams(String params) throws Exception {
        JSONObject parse=null;
        if(params.startsWith("RSA_")){
            String decrypt = RSAUtils.decryptByPrivateKeyyForBytes(params.substring(4), GetRSAPrivateKey());
            parse = JSONObject.parseObject(decrypt);
        }
        else{
            byte[] decode = Base64.getDecoder().decode(params);
            byte[] decrypt = ECCUtils.decrypt(decode, GetECCPrivateKey());
            String s = new String(decrypt, StandardCharsets.UTF_8);
            parse = JSONObject.parseObject(s);
        }
        RequestParams ret=new RequestParams();
        for(String k:parse.keySet()){
            ret.put(k,parse.get(k));
        }
        return ret;
    }
    public static RequestParams getParamsByJson(String params) throws Exception {
        JSONObject parse=null;
        parse = JSONObject.parseObject(params);
        RequestParams ret=new RequestParams();
        for(String k:parse.keySet()){
            ret.put(k,parse.get(k));
        }
        return ret;
    }

    public static String getException(Exception exception) {
        if(exception==null){return "";}
        try {
            JSONObject jo=new JSONObject();
            jo.put("message",exception.getMessage());
            JSONArray ja=new JSONArray();
            StackTraceElement[] stackTrace = exception.getStackTrace();
            for(StackTraceElement stack:stackTrace){
                JSONObject o1 = new JSONObject();
                o1.put("fileName",stack.getFileName());
                o1.put("className",stack.getClassName());
                o1.put("methodName",stack.getMethodName());
                o1.put("lineNumber",stack.getLineNumber());
                ja.add(o1);
            }
            jo.put("stackTrace", ja);
            jo.put("cause",getThrowable(exception.getCause()));
            return getCurrentRequestPrefix() + jo.toJSONString();
        }catch (Exception ex){
            //logger.error(ex.getMessage(),ex.getStackTrace());
        }
        return getCurrentRequestPrefix() + exception.getMessage();
    }
    private static  JSONObject getThrowable(Throwable cause){
        if(cause!=null){
            JSONObject jo=new JSONObject();
            jo.put("message",cause.getMessage());
            JSONArray ja=new JSONArray();
            StackTraceElement[] stackTrace = cause.getStackTrace();
            for(StackTraceElement stack:stackTrace){
                JSONObject o1 = new JSONObject();
                o1.put("fileName",stack.getFileName());
                o1.put("className",stack.getClassName());
                o1.put("methodName",stack.getMethodName());
                o1.put("lineNumber",stack.getLineNumber());
                ja.add(o1);
            }
            jo.put("stackTrace", ja);
            jo.put("cause",getThrowable(cause.getCause()));
            return  jo;
        }
        else{return  null;}
    }
    public static String  getRequestFormData(HttpServletRequest request) {
        try {
            if(request.getMethod().equals("POST")){
                Collection<Part> parts = request.getParts();
                if(parts==null){return "";}
                JSONObject jo=new JSONObject();
                for (Part pt : parts) {
                    jo.put(pt.getName(),pt);
                }
                return jo.toJSONString();
            }
        }catch (Exception ex){
            //logger.error(ex.getMessage(),ex.getStackTrace());
        }
        return "";
    }
    public static HttpServletRequest getCurrentRequest(){
        try {
            HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
            if(request!=null){
                return  request;
            }
        }catch (Exception ex){}
        return null;
    }
    public static String getCurrentRequestPrefix(){
        HttpServletRequest request=getCurrentRequest();
        if(request!=null){
            return request.getRemoteAddr()+" --> ";
        }
        return "";
    }
}
