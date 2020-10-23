package com.pachain.voting.service.controller.API;

import com.alibaba.fastjson.JSONObject;
import com.pachain.voting.service.common.ECCUtils;
import com.pachain.voting.service.common.GlobalUtils;
import com.pachain.voting.service.common.RequestParams;
import com.pachain.voting.service.entities.modules.Voter;
import com.pachain.voting.service.entities.services.VoterService;
import com.pachain.voting.service.fabric.config.ChainCodeConfig;
import com.pachain.voting.service.sms.Nexmo;
import com.pachain.voting.service.sms.Twilio;
import com.pachain.voting.service.fabric.*;
import org.hyperledger.fabric.gateway.Identity;
import org.hyperledger.fabric.gateway.X509Identity;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.Peer;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.ECPrivateKey;
import java.util.List;
import java.util.UUID;
import java.util.Base64;

@RestController
@RequestMapping("/api/voter")
public class VoterController {
    @Autowired
    private VoterService voterService;
    @Autowired
    private Nexmo nexmo;
    @Autowired
    private Twilio twilio;
    private static Logger logger = org.slf4j.LoggerFactory.getLogger(InitController.class);

    @RequestMapping(value = "/register",method = RequestMethod.POST)
    public  JSONObject RegisterVoter(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String publicKey = "";
        String encryptKey = "";
        String appAuthorizationId = "";
        String voterId = "";
        String precinctId = "";
        String precinctNumber = "";
        String email = "";
        String firstName = "";
        String middleName = "";
        String lastName = "";
        String nameSuffix = "";
        String cellphone = "";
        String state = "";
        String county = "";
        String city = "";
        String address = "";
        String images = "";
        String keyType = "";
        String signature = "";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            publicKey = requestParams.getString("publicKey", "");
            encryptKey = requestParams.getString("encryptKey", "");
            appAuthorizationId = requestParams.getString("appAuthorizationId", "");
            voterId = requestParams.getString("voterId", "");
            precinctId = requestParams.getString("precinctId", "");
            precinctNumber = requestParams.getString("precinctNumber", "");
            email = requestParams.getString("email", "");
            firstName = requestParams.getString("firstName", "");
            middleName = requestParams.getString("middleName", "");
            lastName = requestParams.getString("lastName", "");
            nameSuffix = requestParams.getString("nameSuffix", "");
            cellphone = requestParams.getString("cellphone", "");
            state = requestParams.getString("state", "");
            county = requestParams.getString("county", "");
            city = requestParams.getString("city", "");
            address = requestParams.getString("address", "");
            images = requestParams.getString("images", "");
            keyType = requestParams.getString("keyType", "");
            signature = requestParams.getString("signature", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        if(!GlobalUtils.verifySignature(keyType,publicKey,publicKey,signature)){
            ret.put("ret",false);
            ret.put("error","signature not match");
            return ret;
        }
        Voter voter=null;
        try{
            if(voterId==null || voterId.isEmpty() || voterId.trim().length()==0){
                ret.put("ret",false);
                ret.put("error","voterId  is missing");
            }
            else{
                voter = voterService.loadByVoterID(voterId);
                if(voter!=null){
                    ret.put("ret",false);
                    ret.put("error","voterId  \""+voterId+"\"  is exists");
                }
            }
            if(email==null || email.isEmpty() || email.trim().length()==0) {
                ret.put("ret",false);
                ret.put("error","email  is missing");
            }
            else{
                voter = voterService.loadByEmail(email);
                if(voter!=null){
                    ret.put("ret",false);
                    ret.put("error","email  \""+email+"\"  is exists");
                }
            }
            if(voter==null){
                if((precinctId==null || precinctId.isEmpty() || precinctId.equals("0")) && precinctNumber.length()>0){
                    precinctId = ((Integer)voterService.getPrecinctIDByNumber(state,county,precinctNumber)).toString();
                }
                voter=new Voter();
                voter.setPublicKey(publicKey);
                voter.setEncryptKey(encryptKey);
                voter.setVoterID(voterId);
                voter.setPrecinctID(precinctId);
                voter.setPrecinctNumber(precinctNumber);
                voter.setEmail(email);
                voter.setFirstName(firstName);
                voter.setMiddleName(middleName);
                voter.setLastName(lastName);
                voter.setNameSuffix(nameSuffix);
                voter.setCellphone(cellphone);
                voter.setState(state);
                voter.setCounty(county);
                voter.setCity(city);
                voter.setAddress(address);
                //voter.setPhoto(photo);
                //voter.setCertificate(certificate);
                //Step1: Register
                voterService.register(voter);
                ret.put("ret",true);
                voter =  voterService.loadByVoterID(voterId);
                voterService.updatePublicKey(voter.getId(),keyType,publicKey,encryptKey);
                try{
                    if(images!=null && images.length()>0){
                        String[] split = images.split(",");
                        for(String s: images.split(",")){
                            try {
                                voterService.appendImage(voter.getId(), Integer.parseInt(s));
                            }catch(Exception ee){
                                logger.error(ee.getMessage()+"\n"+ee.getStackTrace());
                            }
                        }
                    }
                }catch (Exception ex){
                    logger.error(GlobalUtils.getException(ex));
                    try {
                        voterService.deleteByID(voter.getId());
                    }catch(Exception ee){
                        logger.error(ee.getMessage()+"\n"+ee.getStackTrace());
                    }
                    ret.put("ret",false);
                    ret.put("error",ex.getMessage());
                }
            }
            return ret;
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
            if(voter!=null){
                try {
                    voterService.deleteByID(voter.getId());
                }catch (Exception e){
                    logger.error(e.getMessage()+"\n"+e.getStackTrace());
                }
            }
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
        }
        return  ret;
    }

    @RequestMapping(value = "/shakehands",method = RequestMethod.POST)
    public  JSONObject Shakehands(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String publicKey="";
        String appAuthorizationId="";
        String signature="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            publicKey = requestParams.getString("publicKey", "");
            appAuthorizationId = requestParams.getString("appAuthorizationId", "");
            signature = requestParams.getString("signature", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        Voter voter = voterService.loadByPublicKey(publicKey);
        if(voter==null){
            ret.put("ret",false);
            ret.put("error","An identity for the publicKey \""+publicKey+"\" not exists");
        }
        else if(voter.getPublicKey()!=publicKey){
            ret.put("ret",false);
            ret.put("error","publicKey not match");
        }
        if(!GlobalUtils.verifySignature(voter.getKeyType(),publicKey,publicKey,signature)){
            ret.put("ret",false);
            ret.put("error","signature not match");
        }
        else{
            try{
                Identity identity = WalletClient.GetUserIdentity(voter.getWalletID());
                if(identity!=null){
                    UUID uuid = UUID.randomUUID();
                    voter.setAccessToken(uuid.toString().replace("-",""));
                    voterService.updateAccessToken(voter.getId(),voter.getAccessToken());
                    ret.put("ret",true);
                    ret.put("response",GlobalUtils.encryptData(voter.getKeyType(),voter.getPublicKey(),voter.getAccessToken()));
                }
                else{
                    ret.put("ret",false);
                    ret.put("error","Not found the wallet");
                }
            }catch (Exception ex){
                ret.put("ret",false);
                ret.put("error",ex.getMessage());
                logger.error(GlobalUtils.getException(ex));
            }
        }
        return  ret;
    }

    @RequestMapping(value = "/me",method = RequestMethod.POST)
    public  JSONObject Me(@RequestParam("params") String params) throws Exception {
        String accessToken="";
        String tempParams="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            accessToken = requestParams.getString("accessToken", "");
            tempParams = requestParams.getString("tempParams", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        Voter voter = voterService.loadByAccessToken(accessToken);
        JSONObject ret=new JSONObject();
        if(voter==null){
            ret.put("ret",false);
            ret.put("error","An identity for the accessToken \""+accessToken+"\" not exists");
        }
        String signature ="";
        try {
            X509Identity identity = (X509Identity) WalletClient.GetUserIdentity(voter.getWalletID());
            tempParams = GlobalUtils.decryptData((ECPrivateKey) identity.getPrivateKey(), tempParams);
            RequestParams requestParams = GlobalUtils.getParamsByJson(tempParams);
            signature=requestParams.getString("signature","");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        if(!GlobalUtils.verifySignature(voter.getKeyType(),voter.getPublicKey(),accessToken,signature)){
            ret.put("ret",false);
            ret.put("error","signature not match");
        }
        else{
            try{
                ret.put("ret",true);
                JSONObject rt=new JSONObject();
                rt.put("publicKey",voter.getPublicKey());
                rt.put("voterId",voter.getVoterID());
                rt.put("email",voter.getEmail());
                rt.put("firstName",voter.getFirstName());
                rt.put("middleName",voter.getMiddleName());
                rt.put("lastName",voter.getLastName());
                rt.put("nameSuffix",voter.getNameSuffix());
                rt.put("cellphone",voter.getCellphone());
                rt.put("state",voter.getState());
                rt.put("address",voter.getAddress());
                rt.put("photo",voter.getPhoto());
                rt.put("certificateType",voter.getCertificateType());
                rt.put("certificate",voter.getCertificate());
                String response = rt.toJSONString();
                ret.put("response",GlobalUtils.encryptData(voter.getKeyType(),voter.getEncryptKey(),response));
            }catch (Exception ex){
                ret.put("ret",false);
                ret.put("error",ex.getMessage());
                logger.error(GlobalUtils.getException(ex));
            }
        }
        return  ret;
    }

    @RequestMapping(value = "/updatephoto",method = RequestMethod.POST)
    public  JSONObject UpdatePhoto(@RequestParam("params") String params){
        String publicKey="";
        String voterID="";
        String photo="";
        String keyType="";
        String signature="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            publicKey = requestParams.getString("publicKey", "");
            voterID = requestParams.getString("voterID", "");
            photo = requestParams.getString("photo", "");
            keyType = requestParams.getString("keyType", "");
            signature = requestParams.getString("signature", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        Voter voter = voterService.loadByVoterID(voterID);
        JSONObject ret=new JSONObject();
        if(voter==null){
            ret.put("ret",false);
            ret.put("error","An identity for the publicKey \""+publicKey+"\" not exists");
        }
        if(!GlobalUtils.verifySignature(keyType,publicKey,publicKey,signature)){
            ret.put("ret",false);
            ret.put("error","signature not match");
        }
        else{
            try{
                voterService.updatePhoto(voter.getId(),photo);
                ret.put("ret",true);
            }catch (Exception ex){
                ret.put("ret",false);
                ret.put("error",ex.getMessage());
                logger.error(GlobalUtils.getException(ex));
            }
        }
        return  ret;
    }

    @RequestMapping(value = "/updateimage",method = RequestMethod.POST)
    public  JSONObject UpdateImage(@RequestParam("params") String params){
        String publicKey="";
        String voterID="";
        String type="";
        String image="";
        String keyType="";
        String signature="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            publicKey = requestParams.getString("publicKey", "");
            voterID = requestParams.getString("voterID", "");
            type = requestParams.getString("type", "");
            image = requestParams.getString("image", "");
            keyType = requestParams.getString("keyType", "");
            signature = requestParams.getString("signature", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        JSONObject ret=new JSONObject();
        if(!GlobalUtils.verifySignature(keyType,publicKey,publicKey,signature)){
            ret.put("ret",false);
            ret.put("error","signature not match");
        }
        else{
            try{
                if(voterID==null || voterID.length()<=0 || voterID.equals("0")){
                    UUID uuid = UUID.randomUUID();
                    int id = voterService.updateTempImage(uuid.toString(), type, image);
                    ret.put("id",id);
                    ret.put("ret",true);
                }
                else{
                    Voter voter = voterService.loadByVoterID(voterID);
                    if(voter==null){
                        ret.put("ret",false);
                        ret.put("error","voterID \""+voterID+"\" not exists");
                    }
                    else {
                        int id = voterService.updateImage(voter.getId(), type, image);
                        ret.put("id", id);
                        ret.put("ret", true);
                    }
                }
            }catch (Exception ex){
                ret.put("ret",false);
                ret.put("error",ex.getMessage());
                logger.error(GlobalUtils.getException(ex));
            }
        }
        return  ret;
    }

    @RequestMapping(value = "/sendsmsmessage",method = RequestMethod.POST)
    public  JSONObject SendSMSMessage(@RequestParam("params") String params){
        String publicKey="";
        String to="";
        String message="";
        String keyType="";
        String signature="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            publicKey = requestParams.getString("publicKey", "");
            to = requestParams.getString("to", "");
            message = requestParams.getString("message", "");
            keyType = requestParams.getString("keyType", "");
            signature = requestParams.getString("signature", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        JSONObject ret=new JSONObject();
        if(!GlobalUtils.verifySignature(keyType,publicKey,publicKey,signature)){
            ret.put("ret",false);
            ret.put("error","signature not match");
        }
        else{
            try{
                boolean sended=false;
                if(nexmo.IsReady()){
                    if(to.startsWith("+")){
                        to.replaceFirst("\\+","");
                    }
                    sended = nexmo.SendMessage(to,message);
                }
                if(!sended && twilio.IsReady()){
                    if(!to.startsWith("+")){
                        to="+"+to;
                    }
                    sended= twilio.SendMessage(to,message);
                }
                ret.put("ret",sended);
            }catch (Exception ex){
                ret.put("ret",false);
                ret.put("error",ex.getMessage());
                logger.error(GlobalUtils.getException(ex));
            }
        }
        return  ret;
    }

    @RequestMapping(value = "/verify",method = RequestMethod.POST)
    public  JSONObject Verify(@RequestParam("params") String params){
        String publicKey="";
        String signature="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            publicKey = requestParams.getString("publicKey", "");
            signature = requestParams.getString("signature", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        JSONObject ret=new JSONObject();
        Voter voter = voterService.loadByPublicKey(publicKey);
        if(voter==null){
            ret.put("ret",false);
            ret.put("error","An identity for the publicKey \""+publicKey+"\" not exists");
        }
        if(!GlobalUtils.verifySignature(voter.getKeyType(),voter.getPublicKey(),publicKey,signature)){
            ret.put("ret",false);
            ret.put("error","signature not match");
        }
        else{
            try{
                ChainCodeConfig chainCode = FabricConfig.VoterChainCode;
                //Step2： Wallet Register &  enroll
                JSONObject rt=new JSONObject();
                String walletID = voter.getWalletID();
                if(walletID.isEmpty() || walletID.length()<=0){
                    voter.setWalletID("Wallet_"+voter.getVoterID()+"_"+voter.getLastModify().getTime());
                }
                X509Identity identity = (X509Identity)WalletClient.GetUserIdentity(voter.getWalletID());
                if(identity==null){
                    WalletResponse walletResponse = WalletClient.NewUser(voter.getWalletID());
                    if(walletResponse.getStatus()==1) {
                        identity = walletResponse.getIdentity();
                    }
                    else{
                        ret.put("ret",false);
                        ret.put("error","create wallet failed: "+walletResponse.getMessage());
                        return  ret;
                    }
                }
                voterService.updateWalletID(voter.getVoterID(), voter.getWalletID(), identity.getCertificate().toString(), identity.getPrivateKey().toString(), FabricConfig.FirstOrganization().getMSPID(), "", "");
                Base64.Encoder encoder = Base64.getEncoder();
                String ps = encoder.encodeToString(identity.getCertificate().getPublicKey().getEncoded());
                rt.put("walletID", voter.getWalletID());
                rt.put("publickey", ps);
                rt.put("signature", encoder.encodeToString(ECCUtils.sign(ps, (ECPrivateKey) identity.getPrivateKey())));
                rt.put("approved", DateTime.now().toDate().getTime());
                if(voter.getApproved()<=0){
                    HFClient client = FabricClient.getClient();
                    client.setUserContext(WalletClient.GetUser(voter.getWalletID()));
                    Channel channel=FabricClient.getChannel(client, FabricConfig.Channel.getName());
                    List<Peer> endorsePeers = FabricClient.getEndorsePeers(client,chainCode.getEndorsement());
                    for(Peer p:endorsePeers){
                        channel.addPeer(p);
                    }
                    channel.initialize();
                    int precinctID = 0;
                    try{
                        precinctID = Integer.parseInt(voter.getPrecinctID());
                    }
                    catch(Exception ex){
                        precinctID=0;
                        logger.error(GlobalUtils.getException(ex));
                    }
                    JSONObject pms=new JSONObject();
                    pms.put("voterid",voter.getVoterID());
                    pms.put("state",voter.getState());
                    pms.put("county",voter.getCounty());
                    pms.put("publickey",voter.getPublicKey());
                    String pid = voter.getPrecinctID();
                    try{
                        pms.put("precinctid",Integer.parseInt(pid));
                    }catch (Exception ex){
                        pms.put("precinctid",0);
                    }
                    JSONObject resp = FabricClient.invoke(client, channel, chainCode.getVoter(), "registerUser", pms.toJSONString());
                    if(resp.containsKey("ret") && !resp.getBoolean("ret")){
                        ret.put("ret",false);
                        if(resp.containsKey("msg")){
                            ret.put("error",resp.getString("msg"));
                        }
                        else{
                            ret.put("error",resp);
                        }
                    }
                    else{
                        voterService.approved(voter.getId(), resp.getString("txid"),1,DateTime.now().toDate());
                        ret.put("ret",true);
                        try {
                            UUID uuid = UUID.randomUUID();
                            voter.setAccessToken(uuid.toString().replace("-", ""));
                            voterService.updateAccessToken(voter.getId(), voter.getAccessToken());
                            rt.put("accessToken", voter.getAccessToken());
                            String response = rt.toJSONString();
                            ret.put("response", GlobalUtils.encryptData(voter.getKeyType(), voter.getEncryptKey(), response));
                        }
                        catch (Exception ex){
                            ret.put("ret",false);
                            ret.put("error",ex.getMessage());
                            logger.error(GlobalUtils.getException(ex));
                        }
                    }
                }
                else{
                    ret.put("ret",true);
                }
                if(ret.getBoolean("ret")){
                    String response = rt.toJSONString();
                    ret.put("response",GlobalUtils.encryptData(voter.getKeyType(),voter.getEncryptKey(),response));
                }
            }catch (Exception ex){
                ret.put("ret",false);
                ret.put("error",ex.getMessage());
                logger.error(GlobalUtils.getException(ex));
            }
        }
        return  ret;
    }
}
