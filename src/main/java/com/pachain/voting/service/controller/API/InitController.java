package com.pachain.voting.service.controller.API;

import com.alibaba.fastjson.JSONObject;
import com.pachain.voting.service.common.ECCUtils;
import com.pachain.voting.service.common.GlobalUtils;
import com.pachain.voting.service.common.RequestParams;
import com.pachain.voting.service.fabric.*;
import org.hyperledger.fabric.gateway.X509Identity;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.Peer;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.*;

@RestController
public class InitController{
    private static Logger logger = org.slf4j.LoggerFactory.getLogger(InitController.class);

    @RequestMapping("/api/getpublickey")
    public JSONObject GetPublicKey(@RequestParam(value = "kp",required = false, defaultValue = "") String kp){
        JSONObject ret=new JSONObject();
        try {
            if(kp.equalsIgnoreCase("rsa")){
                ret.put("ret",true);
                ret.put("publicKey",GlobalUtils.GetRSAPublicKey());
            }
            else{
                ret.put("ret",true);
                ret.put("publicKey",GlobalUtils.GetECCPublicKey());
            }
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return  ret;
    }

    @RequestMapping("/api/newclient")
    public JSONObject NewClient(@RequestParam("params") String params){
        String token="";
        String userName="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            token = requestParams.getString("token", "");
            userName = requestParams.getString("userName", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        JSONObject ret=new JSONObject();
        try{
            X509Identity admin = (X509Identity) WalletClient.GetUserIdentity("admin");
            Base64.Encoder encoder = Base64.getEncoder();
            if(!WalletClient.CheckToken(token)){
                ret.put("ret", false);
                ret.put("error", "token not matched");
            }
            else{
                if(userName.isEmpty() || userName.length()==0){
                    userName= "WALLET_RAW_"+DateTime.now().toDate().getTime();
                }
                WalletResponse walletResponse = WalletClient.NewUser(userName);
                if(walletResponse.getStatus()==1){
                    X509Identity identity = walletResponse.getIdentity();
                    ret.put("ret", true);
                    ret.put("token", encoder.encodeToString(ECCUtils.encrypt(userName.getBytes(StandardCharsets.UTF_8),(ECPublicKey)admin.getCertificate().getPublicKey())));
                    ret.put("publickey", encoder.encodeToString(identity.getCertificate().getPublicKey().getEncoded()));
                }
                else{
                    ret.put("ret", false);
                    ret.put("error", walletResponse.getMessage());
                }
            }
        }
        catch (Exception ex){
            ret.put("ret", false);
            ret.put("error", ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return  ret;
    }

    @RequestMapping("/api/query")
    public  JSONObject Query(@RequestBody Map<String, String> params){
        JSONObject ret=new JSONObject();
        try{
            HFClient client = FabricClient.getClient();
            client.setUserContext(new PeerAdmin(FabricConfig.FirstOrganization().getName()));
            Channel channel=FabricClient.getChannel(client, FabricConfig.Channel.getName());
            List<Peer> endorsePeers = FabricClient.getEndorsePeers(client,FabricConfig.LastedElectionChainCode().getEndorsement());
            for(Peer p:endorsePeers){
                channel.addPeer(p);
            }
            channel.initialize();
            String chainCode=params.containsKey("chaincode")?params.get("chaincode"):"";
            String action=params.containsKey("action")?params.get("action"):"";
            List<String> ps=new ArrayList<String>() ;
            int pIndex=1;
            while (params.containsKey("param"+pIndex)){
                ps.add(params.get("param"+pIndex));
                pIndex++;
            }
            String[] args=null;
            if(!ps.isEmpty()){
                args=new String[ps.size()];
                ps.toArray(args);
            }
            JSONObject resp = FabricClient.query(client, channel, chainCode, action,args);
            ret.put("ret",resp.containsValue("ret") ? resp.getBoolean("ret"):true);
            ret.put("response",resp);
        }catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return  ret;
    }

    @RequestMapping("/api/invork")
    public  JSONObject Invork(@RequestBody Map<String, String> params){
        JSONObject ret=new JSONObject();
        try{
            HFClient client = FabricClient.getClient();
            client.setUserContext(new PeerAdmin(FabricConfig.FirstOrganization().getName()));
            Channel channel=FabricClient.getChannel(client, FabricConfig.Channel.getName());
            List<Peer> endorsePeers = FabricClient.getEndorsePeers(client,FabricConfig.LastedElectionChainCode().getEndorsement());
            for(Peer p:endorsePeers){
                channel.addPeer(p);
            }
            channel.initialize();
            String chainCode=params.containsKey("chaincode")?params.get("chaincode"):"";
            String action=params.containsKey("action")?params.get("action"):"";
            List<String> ps=new ArrayList<String>() ;
            int pIndex=1;
            while (params.containsKey("param"+pIndex)){
                ps.add(params.get("param"+pIndex));
                pIndex++;
            }
            String[] args=null;
            if(!ps.isEmpty()){
                args=new String[ps.size()];
                ps.toArray(args);
            }
            JSONObject resp = FabricClient.invoke(client, channel, chainCode, action,args);
            ret.put("ret",resp.containsValue("ret") ? resp.getBoolean("ret"):true);
            ret.put("response",resp);
        }catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return  ret;
    }

    @RequestMapping(value = "/api/ead",method = RequestMethod.POST)
    public String EAD(@RequestParam("params") String params){
        String opt="";
        String key="";
        String data="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            opt = requestParams.getString("opt", "");
            key = requestParams.getString("key", "");
            data = requestParams.getString("data", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        JSONObject ret=new JSONObject();
        try{
                URLDecoder urlDecoder = new URLDecoder();
                Base64.Decoder decoder = Base64.getDecoder();
                Base64.Encoder encoder = Base64.getEncoder();
                //key=URLDecoder.decode(key,"UTF-8");
                if(opt.equals("d")){
                    ECPrivateKey privateKey=ECCUtils.getPrivateKeyFromString(key);
                    ret.put("ret", true);
                    ret.put("data", new String(ECCUtils.decrypt(decoder.decode(data),privateKey),StandardCharsets.UTF_8));
                }
                else{
                    ECPublicKey publicKey =ECCUtils.getPublicKeyFromString(key);
                    ret.put("ret", true);
                    ret.put("data", encoder.encodeToString(ECCUtils.encrypt(data.getBytes(StandardCharsets.UTF_8),publicKey)));
                }
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return ret.toJSONString();
    }

    @RequestMapping(value = "/api/sign",method = RequestMethod.POST)
    public String sign(@RequestParam("params") String params){
        String privatekey="";
        String content="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            privatekey = requestParams.getString("privatekey", "");
            content = requestParams.getString("content", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        JSONObject ret=new JSONObject();
        ECPrivateKey pKey = null;
        try{
            pKey = ECCUtils.getPrivateKeyFromString(privatekey);
        }catch (Exception ex){
            ret.put("ret","false");
            ret.put("error",ex.getMessage());
        }
        try{
            byte[] sign = ECCUtils.sign(content, pKey);
            ret.put("ret","true");
            ret.put("sign",Base64.getEncoder().encodeToString(sign));
        }catch (Exception ex){
            ret.put("ret","false");
            ret.put("error",ex.getMessage());
        }
        return ret.toJSONString();
    }

    @RequestMapping(value = "/api/verifysign",method = RequestMethod.POST)
    public String verifySign(@RequestParam("params") String params){
        String publickey="";
        String content="";
        String signature="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            publickey = requestParams.getString("publickey", "");
            content = requestParams.getString("content", "");
            signature = requestParams.getString("signature", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        JSONObject ret=new JSONObject();
        ECPublicKey pKey = null;
        try{
            pKey = ECCUtils.getPublicKeyFromString(publickey);
        }catch (Exception ex){
            ret.put("ret","false");
            ret.put("error",ex.getMessage());
        }
        try{
            if(ECCUtils.verify(content, java.util.Base64.getDecoder().decode(signature),pKey)){
                ret.put("ret","true");
            }
            else{
                ret.put("ret","false");
                ret.put("error","verify failed");
            }
        }catch (Exception ex){
            ret.put("ret","false");
            ret.put("error",ex.getMessage());
        }
        return ret.toJSONString();
    }

    @RequestMapping(value = "/api/decrypt",method = RequestMethod.POST)
    public String decrypt(@RequestParam("params") String params){
        String privatekey="";
        String content="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            privatekey = requestParams.getString("privatekey", "");
            content = requestParams.getString("content", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        JSONObject ret=new JSONObject();
        ECPrivateKey pKey = null;
        try{
            pKey = ECCUtils.getPrivateKeyFromString(privatekey);
        }catch (Exception ex){
            ret.put("ret","false");
            ret.put("error",ex.getMessage());
        }
        try{
            byte[] decrypt = ECCUtils.decrypt(Base64.getDecoder().decode(content), pKey);
            String resp = new String(decrypt, "UTF-8");
            ret.put("ret","true");
            ret.put("content",resp);
        }catch (Exception ex){
            ret.put("ret","false");
            ret.put("error",ex.getMessage());
        }
        return ret.toJSONString();
    }

    @RequestMapping(value = "/api/encrypt",method = RequestMethod.POST)
    public String encrypt(@RequestParam("params") String params){
        String publickey="";
        String content="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            publickey = requestParams.getString("publickey", "");
            content = requestParams.getString("content", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        JSONObject ret=new JSONObject();
        ECPublicKey pKey = null;
        try{
            pKey = ECCUtils.getPublicKeyFromString(publickey);
        }catch (Exception ex){
            ret.put("ret","false");
            ret.put("error",ex.getMessage());
        }
        try{
            byte[] encrypt = ECCUtils.encrypt(content.getBytes("UTF-8"), pKey);
            String resp = Base64.getEncoder().encodeToString(encrypt);
            ret.put("ret","true");
            ret.put("content",resp);
        }catch (Exception ex){
            ret.put("ret","false");
            ret.put("error",ex.getMessage());
        }
        return ret.toJSONString();
    }

    @RequestMapping(value = "/api/getTransaction",method = RequestMethod.POST)
    public String getTransaction(@RequestParam("txid") String txid){
        JSONObject ret=new JSONObject();
        try {
            HFClient client = FabricClient.getClient();
            client.setUserContext(new PeerAdmin(FabricConfig.FirstOrganization().getName()));
            Channel channel = FabricClient.getChannel(client, FabricConfig.Channel.getName());
            channel.addPeer(FabricClient.getFirstPeer(client));
            channel.initialize();
            JSONObject transaction = FabricClient.getTransaction(channel, txid);
            ret.put("ret",true);
            ret.put("response",transaction);
        }catch (Exception ex){
            ret.put("ret",false);
            ret.put("response",ex.getMessage());
        }
        return  ret.toJSONString();
    }

    @RequestMapping("/api/requestnomatch")
    public String RequestNoMatch(HttpServletRequest request){
        JSONObject ret=new JSONObject();
        ret.put("ret",false);
        ret.put("error","Request Not Match: "+request.getRequestURI());
        return  ret.toJSONString();
    }
}
