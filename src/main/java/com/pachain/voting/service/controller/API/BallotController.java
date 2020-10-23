package com.pachain.voting.service.controller.API;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.pachain.voting.service.common.ECCUtils;
import com.pachain.voting.service.common.GlobalUtils;
import com.pachain.voting.service.common.RequestParams;
import com.pachain.voting.service.entities.modules.Voter;
import com.pachain.voting.service.entities.services.VoterService;
import com.pachain.voting.service.fabric.FabricClient;
import com.pachain.voting.service.fabric.FabricConfig;
import com.pachain.voting.service.fabric.PeerAdmin;
import com.pachain.voting.service.fabric.WalletClient;
import com.pachain.voting.service.fabric.config.ChainCodeConfig;
import org.bouncycastle.util.encoders.Base64;
import org.hyperledger.fabric.gateway.X509Identity;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.Peer;
import org.omg.PortableInterceptor.RequestInfo;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPrivateKey;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;

@RestController
@RequestMapping("/api/ballots")
public class BallotController {
    @Autowired
    private VoterService voterService;
    private static Logger logger = org.slf4j.LoggerFactory.getLogger(BallotController.class);

    @RequestMapping(value = "/getballots",method = RequestMethod.POST)
    public String GetBallots(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String signature="";
        String accessToken="";
        String tmpParams="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            accessToken = requestParams.getString("accessToken", "");
            tmpParams = requestParams.getString("params", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        try{
            Voter voter = voterService.loadByAccessToken(accessToken);
            if(voter==null){
                ret.put("ret",false);
                ret.put("error","An identity for the accessToken \""+accessToken+"\" not exists");
            }
            try {
                X509Identity identity = (X509Identity) WalletClient.GetUserIdentity(voter.getWalletID());
                tmpParams = GlobalUtils.decryptData((ECPrivateKey) identity.getPrivateKey(), tmpParams);
                RequestParams requestParams = GlobalUtils.getParamsByJson(tmpParams);
                signature=requestParams.getString("signature","");
            }
            catch (Exception ex){
                logger.error(GlobalUtils.getException(ex));
            }
            if(!GlobalUtils.verifySignature(voter.getKeyType(),voter.getPublicKey(),accessToken,signature)){
                ret.put("ret",false);
                ret.put("error","signature not match");
            }
            else {
                HFClient client = FabricClient.getClient();
                client.setUserContext(WalletClient.GetUser(voter.getWalletID()));
                Channel channel = FabricClient.getChannel(client, FabricConfig.Channel.getName());
                channel.addPeer(FabricClient.getFirstPeer(client));
                channel.initialize();
                JSONArray ja=new JSONArray();
                for(String ek:FabricConfig.ElectionChainCodes.keySet()){
                    JSONObject resp = FabricClient.query(client, channel, FabricConfig.ElectionChainCode(ek).getBallot(), "queryBallot", voter.getPublicKey());
                    if (resp.containsKey("ret") && !resp.getBooleanValue("ret")) {
                        ret.put("ret", false);
                        ret.put("response", resp);
                         break;
                    } else {
                        if(resp.containsKey("data")){
                            JSONObject objects = new JSONObject();
                            objects.put("electionKey",ek);
                            objects.put("data",resp.getJSONObject("data"));
                            ja.add(objects);
                        }
                    }
                }
                if(!ret.containsKey("ret")){
                    ret.put("ret", true);
                    String response = ja.toJSONString();
                    ret.put("response", GlobalUtils.encryptData(voter.getKeyType(),voter.getEncryptKey(),response));
                }
            }
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return ret.toJSONString();
    }

    @RequestMapping(value = "/getballot",method = RequestMethod.POST)
    public String GetBallot(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String signature="";
        String accessToken="";
        String tmpParams="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            accessToken = requestParams.getString("accessToken", "");
            tmpParams = requestParams.getString("params", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        try{
            Voter voter = voterService.loadByAccessToken(accessToken);
            if(voter==null){
                ret.put("ret",false);
                ret.put("error","An identity for the accessToken \""+accessToken+"\" not exists");
            }
            try {
                X509Identity identity = (X509Identity) WalletClient.GetUserIdentity(voter.getWalletID());
                tmpParams = GlobalUtils.decryptData((ECPrivateKey) identity.getPrivateKey(), tmpParams);
                RequestParams requestParams = GlobalUtils.getParamsByJson(tmpParams);
                tmpParams=requestParams.getString("params","");
                signature=requestParams.getString("signature","");
            }
            catch (Exception ex){
                logger.error(GlobalUtils.getException(ex));
            }
            if(!GlobalUtils.verifySignature(voter.getKeyType(),voter.getPublicKey(),accessToken,signature)){
                ret.put("ret",false);
                ret.put("error","signature not match");
            }
            else {
                final ECPrivateKey pKey = ECCUtils.getPrivateKeyFromString(voter.getWalletPrivateKey());
                JSONObject pObject = JSONObject.parseObject(new String(ECCUtils.decrypt(Base64.decode(tmpParams), pKey), StandardCharsets.UTF_8));
                if (pObject.containsValue("number")) {
                    String number = pObject.getString("number");
                    HFClient client = FabricClient.getClient();
                    client.setUserContext(WalletClient.GetUser(voter.getWalletID()));
                    Channel channel = FabricClient.getChannel(client, FabricConfig.Channel.getName());
                    channel.addPeer(FabricClient.getFirstPeer(client));
                    channel.initialize();
                    JSONObject pms = new JSONObject();
                    pms.put("ballotnumber", number);
                    JSONArray ja=new JSONArray();
                    for(String ek:FabricConfig.ElectionChainCodes.keySet()){
                        JSONObject resp = FabricClient.query(client, channel, FabricConfig.ElectionChainCode(ek).getBallot(), "queryBallotByBallotNumber", pms.toJSONString());
                        if (resp.containsKey("ret") && !resp.getBooleanValue("ret")) {
                            ret.put("ret", false);
                            ret.put("response", resp);
                            break;
                        } else {
                            if(resp.containsKey("data")){
                                JSONObject objects = new JSONObject();
                                objects.put("electionKey",ek);
                                objects.put("data",resp.getJSONObject("data"));
                                ja.add(objects);
                            }
                        }
                    }
                    if(!ret.containsKey("ret")){
                        ret.put("ret", true);
                        String response = ja.toJSONString();
                        ret.put("response", GlobalUtils.encryptData(voter.getKeyType(),voter.getEncryptKey(),response));
                    }
                } else {
                    ret.put("ret", false);
                    ret.put("error", "not found the number");
                }
            }
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return ret.toJSONString();
    }

    @RequestMapping("/initballot")
    public JSONObject InitBallot(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String electionKey="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            electionKey = requestParams.getString("electionKey", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        try{
            HFClient client = FabricClient.getClient();
            client.setUserContext(new PeerAdmin(FabricConfig.FirstOrganization().getName()));
            Channel channel=FabricClient.getChannel(client, FabricConfig.Channel.getName());
            ChainCodeConfig chainCode = FabricConfig.ElectionChainCode(electionKey);
            List<Peer> endorsePeers = FabricClient.getEndorsePeers(client,chainCode.getEndorsement());
            for(Peer p:endorsePeers){
                channel.addPeer(p);
            }
            channel.initialize();
            JSONObject resp = FabricClient.invoke(client, channel, chainCode.getBallot(), "init","");
            ret.put("ret",resp.containsValue("ret") ? resp.getBoolean("ret"):true);
            ret.put("response",resp);
        }catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return  ret;
    }

    @RequestMapping("/builderballotalluser")
    public JSONObject BuilderBallotAllUser(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String electionKey="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            electionKey = requestParams.getString("electionKey", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        try{
            ChainCodeConfig chainCode = FabricConfig.ElectionChainCode(electionKey);
            HFClient client = FabricClient.getClient();
            client.setUserContext(new PeerAdmin(FabricConfig.FirstOrganization().getName()));
            Channel channel=FabricClient.getChannel(client, FabricConfig.Channel.getName());
            List<Peer> endorsePeers = FabricClient.getEndorsePeers(client,chainCode.getEndorsement());
            for(Peer p:endorsePeers){
                channel.addPeer(p);
            }
            channel.initialize();
            JSONObject resp = FabricClient.invoke(client, channel,chainCode.getBallot(), "builderBallotAllUser","");
            ret.put("ret", resp.containsValue("ret") ? resp.getBoolean("ret") : true);
            ret.put("response", resp);
        }catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return  ret;
    }

    @RequestMapping(value = "/getsampleballots",method = RequestMethod.POST)
    public String GetSampleBallots(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String electionKey="";
        String signature="";
        String accessToken="";
        String tmpParams="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            accessToken = requestParams.getString("accessToken", "");
            tmpParams = requestParams.getString("params", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        try{
            Voter voter = voterService.loadByAccessToken(accessToken);
            if(voter==null){
                ret.put("ret",false);
                ret.put("error","An identity for the accessToken \""+accessToken+"\" not exists");
            }
            try {
                X509Identity identity = (X509Identity) WalletClient.GetUserIdentity(voter.getWalletID());
                tmpParams = GlobalUtils.decryptData((ECPrivateKey) identity.getPrivateKey(), tmpParams);
                RequestParams requestParams = GlobalUtils.getParamsByJson(tmpParams);
                electionKey=requestParams.getString("electionKey","");
                signature=requestParams.getString("signature","");
            }
            catch (Exception ex){
                logger.error(GlobalUtils.getException(ex));
            }
            if(!GlobalUtils.verifySignature(voter.getKeyType(),voter.getPublicKey(),accessToken,signature)){
                ret.put("ret",false);
                ret.put("error","signature not match");
            }
            else {
                ChainCodeConfig chainCode = FabricConfig.ElectionChainCode(electionKey);
                HFClient client = FabricClient.getClient();
                client.setUserContext(WalletClient.GetUser(voter.getWalletID()));
                Channel channel = FabricClient.getChannel(client, FabricConfig.Channel.getName());
                channel.addPeer(FabricClient.getFirstPeer(client));
                channel.initialize();
                JSONObject resp = FabricClient.query(client, channel, chainCode.getBallot(), "queryPrecinctBallots", "");
                if (resp.containsKey("ret") && !resp.getBoolean("ret")) {
                    ret.put("ret", false);
                    ret.put("response", resp);
                } else {
                    ret.put("ret",true);
                    JSONArray objects = new JSONArray();
                    if(resp.containsKey("data")){
                        objects.add(resp.getJSONObject("data"));
                    }
                    String response = objects.toJSONString();
                    ret.put("response", GlobalUtils.encryptData(voter.getKeyType(),voter.getEncryptKey(),response));
                }
            }
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return ret.toJSONString();
    }

    @RequestMapping(value = "/getsampleballot",method = RequestMethod.POST)
    public String GetSampleBallot(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String electionKey="";
        String signature="";
        String accessToken="";
        String tmpParams="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            accessToken = requestParams.getString("accessToken", "");
            tmpParams = requestParams.getString("params", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        try{
            Voter voter = voterService.loadByAccessToken(accessToken);
            if(voter==null){
                ret.put("ret",false);
                ret.put("error","An identity for the accessToken \""+accessToken+"\" not exists");
            }
            try {
                X509Identity identity = (X509Identity) WalletClient.GetUserIdentity(voter.getWalletID());
                tmpParams = GlobalUtils.decryptData((ECPrivateKey) identity.getPrivateKey(), tmpParams);
                RequestParams requestParams = GlobalUtils.getParamsByJson(tmpParams);
                electionKey=requestParams.getString("electionKey","");
                signature=requestParams.getString("signature","");
            }
            catch (Exception ex){
                logger.error(GlobalUtils.getException(ex));
            }
            if(!GlobalUtils.verifySignature(voter.getKeyType(),voter.getPublicKey(),accessToken,signature)){
                ret.put("ret",false);
                ret.put("error","signature not match");
            }
            else {
                ChainCodeConfig chainCode = FabricConfig.ElectionChainCode(electionKey);
                HFClient client = FabricClient.getClient();
                client.setUserContext(WalletClient.GetUser(voter.getWalletID()));
                Channel channel = FabricClient.getChannel(client, FabricConfig.Channel.getName());
                channel.addPeer(FabricClient.getFirstPeer(client));
                channel.initialize();
                JSONObject resp = FabricClient.query(client, channel, chainCode.getBallot(), "queryPrecinctBallot", voter.getPrecinctID());
                if (resp.containsKey("ret") && !resp.getBoolean("ret")) {
                    ret.put("ret", false);
                    ret.put("invoke", resp);
                } else {
                    ret.put("ret",true);
                    String response = resp.toJSONString();
                    ret.put("response", GlobalUtils.encryptData(voter.getKeyType(),voter.getEncryptKey(),response));
                }
            }
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return ret.toJSONString();
    }

    @RequestMapping(value = "/getonionkeys")
    public String GetOnionKeys(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String electionKey="";
        String signature="";
        String accessToken="";
        String tmpParams="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            accessToken = requestParams.getString("accessToken", "");
            tmpParams = requestParams.getString("params", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        try{
            Voter voter = voterService.loadByAccessToken(accessToken);
            if(voter==null){
                ret.put("ret",false);
                ret.put("error","An identity for the accessToken \""+accessToken+"\" not exists");
            }
            try {
                X509Identity identity = (X509Identity) WalletClient.GetUserIdentity(voter.getWalletID());
                tmpParams = GlobalUtils.decryptData((ECPrivateKey) identity.getPrivateKey(), tmpParams);
                RequestParams requestParams = GlobalUtils.getParamsByJson(tmpParams);
                electionKey=requestParams.getString("electionKey","");
                signature=requestParams.getString("signature","");
            }
            catch (Exception ex){
                logger.error(GlobalUtils.getException(ex));
            }
            if(!GlobalUtils.verifySignature(voter.getKeyType(),voter.getPublicKey(),accessToken,signature)){
                ret.put("ret", false);
                ret.put("error", "signature not match");
            } else {
                ChainCodeConfig chainCode = FabricConfig.ElectionChainCode(electionKey);
                HFClient client = FabricClient.getClient();
                client.setUserContext(WalletClient.GetUser(voter.getWalletID()));
                Channel channel = FabricClient.getChannel(client, FabricConfig.Channel.getName());
                channel.addPeer(FabricClient.getFirstPeer(client));
                channel.initialize();
                JSONObject resp = FabricClient.query(client, channel, chainCode.getBallot(), "getOnionKeys", voter.getCounty());
                if (resp.containsKey("ret") && !resp.getBoolean("ret")) {
                    ret.put("ret", false);
                    ret.put("invoke", resp);
                } else {
                    ret.put("ret",true);
                    String response = resp.toJSONString();
                    ret.put("response", GlobalUtils.encryptData(voter.getKeyType(),voter.getEncryptKey(),response));
                }
            }
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return ret.toJSONString();
    }

    /**
     *Public
     * @return
     */
    @RequestMapping(value = "/queryallelection",method = RequestMethod.POST)
    public String queryAllElection(){
        JSONObject ret=new JSONObject();
        try{
            HFClient client = FabricClient.getClient();
            client.setUserContext(new PeerAdmin(FabricConfig.FirstOrganization().getName()));
            Channel channel = FabricClient.getChannel(client, FabricConfig.Channel.getName());
            channel.addPeer(FabricClient.getFirstPeer(client));
            channel.initialize();
            JSONArray ja=new JSONArray();
            for(String ek:FabricConfig.ElectionChainCodes.keySet()){
                JSONObject resp = FabricClient.query(client, channel, FabricConfig.ElectionChainCode(ek).getBallot(), "queryAllElection", null);
                if (resp.containsKey("ret") && !resp.getBooleanValue("ret")) {
                    ret.put("ret", false);
                    ret.put("response", resp);
                    break;
                } else {
                    if(resp.containsKey("data")){
                        JSONObject objects = new JSONObject();
                        objects.put("electionKey",ek);
                        objects.put("data",resp.getJSONArray("data"));
                        ja.add(objects);
                    }
                }
            }
            if(!ret.containsKey("ret")){
                ret.put("ret", true);
                ret.put("response", ja);
            }
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return ret.toJSONString();
    }

    /**
     *Public
     * @return
     */
    @RequestMapping(value = "/queryseatsbyelectionid",method = RequestMethod.POST)
    public String querySeatsByElectionID(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String electionKey="";
        String electionID="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            electionKey = requestParams.getString("electionKey", "");
            electionID = requestParams.getString("electionID", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        try{
            ChainCodeConfig chainCode = FabricConfig.ElectionChainCode(electionKey);
            HFClient client = FabricClient.getClient();
            client.setUserContext(new PeerAdmin(FabricConfig.FirstOrganization().getName()));
            Channel channel = FabricClient.getChannel(client, FabricConfig.Channel.getName());
            channel.addPeer(FabricClient.getFirstPeer(client));
            channel.initialize();
            JSONObject resp = FabricClient.query(client, channel, chainCode.getBallot(), "querySeatsByElectionID", electionID);
            if (resp.containsKey("ret") && !resp.getBoolean("ret")) {
                ret.put("ret", false);
                ret.put("invoke", resp);
            } else {
                ret.put("ret",true);
                ret.put("response", resp);
            }
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return ret.toJSONString();
    }

    @RequestMapping(value = "/initvoteinvite")
    public String initVoteInvite(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String electionKey="";
        String userKey="";
        String status="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            electionKey = requestParams.getString("electionKey", "");
            userKey = requestParams.getString("userKey", "");
            status = requestParams.getString("status", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        try{
            ChainCodeConfig chainCode = FabricConfig.ElectionChainCode(electionKey);
            HFClient client = FabricClient.getClient();
            client.setUserContext(new PeerAdmin(FabricConfig.FirstOrganization().getName()));
            Channel channel = FabricClient.getChannel(client, FabricConfig.Channel.getName());
            List<Peer> endorsePeers = FabricClient.getEndorsePeers(client,chainCode.getEndorsement());
            for(Peer p:endorsePeers){
                channel.addPeer(p);
            }
            channel.initialize();
            String[] ps=new String[3];
            ps[0]=userKey;
            ps[1]=status;
            ps[2]= LocalDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            JSONObject resp = FabricClient.invoke(client, channel, chainCode.getBallot(), "setVoteInvite", ps);
            if (resp.containsKey("ret") && !resp.getBoolean("ret")) {
                ret.put("ret", false);
                ret.put("invoke", resp);
            } else {
                ret.put("ret",true);
                ret.put("response", resp);
            }
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return ret.toJSONString();
    }

    @RequestMapping(value = "/setvoteinvite")
    public String setVoteInvite(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String electionKey="";
        String status="";
        String signature="";
        String accessToken="";
        String tmpParams="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            accessToken = requestParams.getString("accessToken", "");
            tmpParams = requestParams.getString("params", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        try{
            Voter voter = voterService.loadByAccessToken(accessToken);
            if(voter==null){
                ret.put("ret",false);
                ret.put("error","An identity for the accessToken \""+accessToken+"\" not exists");
            }
            try {
                X509Identity identity = (X509Identity) WalletClient.GetUserIdentity(voter.getWalletID());
                tmpParams = GlobalUtils.decryptData((ECPrivateKey) identity.getPrivateKey(), tmpParams);
                RequestParams requestParams = GlobalUtils.getParamsByJson(tmpParams);
                electionKey=requestParams.getString("electionKey","");
                status=requestParams.getString("status","");
                signature=requestParams.getString("signature","");
            }
            catch (Exception ex){
                logger.error(GlobalUtils.getException(ex));
            }
            if(!GlobalUtils.verifySignature(voter.getKeyType(),voter.getPublicKey(),accessToken,signature)){
                ret.put("ret", false);
                ret.put("error", "signature not match");
            } else {
                ChainCodeConfig chainCode = FabricConfig.ElectionChainCode(electionKey);
                HFClient client = FabricClient.getClient();
                client.setUserContext(WalletClient.GetUser(voter.getWalletID()));
                Channel channel = FabricClient.getChannel(client, FabricConfig.Channel.getName());
                List<Peer> endorsePeers = FabricClient.getEndorsePeers(client,chainCode.getEndorsement());
                for(Peer p:endorsePeers){
                    channel.addPeer(p);
                }
                channel.initialize();
                String[] ps=new String[3];
                ps[0]=voter.getPublicKey();
                ps[1]=status;
                ps[2]= LocalDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
                JSONObject resp = FabricClient.invoke(client, channel, chainCode.getBallot(), "setVoteInvite", ps);
                if (resp.containsKey("ret") && !resp.getBoolean("ret")) {
                    ret.put("ret", false);
                    ret.put("invoke", resp);
                } else {
                    ret.put("ret",true);
                    ret.put("response", resp);
                }
            }
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return ret.toJSONString();
    }

    @RequestMapping(value = "/setinvitealluser")
    public String setInviteAllUser (@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String electionKey="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            electionKey = requestParams.getString("electionKey", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        try{
            ChainCodeConfig chainCode = FabricConfig.ElectionChainCode(electionKey);
            HFClient client = FabricClient.getClient();
            client.setUserContext(new PeerAdmin(FabricConfig.FirstOrganization().getName()));
            Channel channel = FabricClient.getChannel(client, FabricConfig.Channel.getName());
            List<Peer> endorsePeers = FabricClient.getEndorsePeers(client,chainCode.getEndorsement());
            for(Peer p:endorsePeers){
                channel.addPeer(p);
            }
            channel.initialize();
            String[] ps=new String[2];
            JSONObject resp = FabricClient.invoke(client, channel, chainCode.getBallot(), "setInviteAllUser", null);
            if (resp.containsKey("ret") && !resp.getBoolean("ret")) {
                ret.put("ret", false);
                ret.put("invoke", resp);
            } else {
                ret.put("ret",true);
                ret.put("response", resp);
            }
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return ret.toJSONString();
    }

    @RequestMapping(value = "/getvoteinvitestatus")
    public String getVoteInviteStatus(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String signature="";
        String accessToken="";
        String tmpParams="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            accessToken = requestParams.getString("accessToken", "");
            tmpParams = requestParams.getString("params", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        try{
            Voter voter = voterService.loadByAccessToken(accessToken);
            if(voter==null){
                ret.put("ret",false);
                ret.put("error","An identity for the accessToken \""+accessToken+"\" not exists");
            }
            try {
                X509Identity identity = (X509Identity) WalletClient.GetUserIdentity(voter.getWalletID());
                tmpParams = GlobalUtils.decryptData((ECPrivateKey) identity.getPrivateKey(), tmpParams);
                RequestParams requestParams = GlobalUtils.getParamsByJson(tmpParams);
                signature=requestParams.getString("signature","");
            }
            catch (Exception ex){
                logger.error(GlobalUtils.getException(ex));
            }
            if(!GlobalUtils.verifySignature(voter.getKeyType(),voter.getPublicKey(),accessToken,signature)){
                ret.put("ret", false);
                ret.put("error", "signature not match");
            } else {
                HFClient client = FabricClient.getClient();
                client.setUserContext(WalletClient.GetUser(voter.getWalletID()));
                Channel channel = FabricClient.getChannel(client, FabricConfig.Channel.getName());
                channel.addPeer(FabricClient.getFirstPeer(client));
                channel.initialize();
                JSONArray ja=new JSONArray();
                for(String ek:FabricConfig.ElectionChainCodes.keySet()){
                    JSONObject resp = FabricClient.query(client, channel, FabricConfig.ElectionChainCode(ek).getBallot(), "getVoteInvite", voter.getPublicKey());
                    if (resp.containsKey("ret") && !resp.getBooleanValue("ret")) {
                        ret.put("ret", false);
                        ret.put("response", resp);
                        break;
                    } else {
                        if(resp.containsKey("data")){
                            JSONObject objects = new JSONObject();
                            objects.put("electionKey",ek);
                            objects.put("data",resp.getJSONObject("data"));
                            ja.add(objects);
                        }
                    }
                }
                if(!ret.containsKey("ret")){
                    ret.put("ret", true);
                    String response = ja.toJSONString();
                    ret.put("response", GlobalUtils.encryptData(voter.getKeyType(),voter.getEncryptKey(),response));
                }
            }
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return ret.toJSONString();
    }

    /**
     *Public
     * @return
     */
    @RequestMapping(value = "/getvoteinvitestatistic")
    public String getVoteInviteStatistic (@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String electionKey="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            electionKey = requestParams.getString("electionKey", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        try{
            HFClient client = FabricClient.getClient();
            client.setUserContext(new PeerAdmin(FabricConfig.FirstOrganization().getName()));
            Channel channel = FabricClient.getChannel(client, FabricConfig.Channel.getName());
            channel.addPeer(FabricClient.getFirstPeer(client));
            channel.initialize();
            JSONArray ja=new JSONArray();
            for(String ek:FabricConfig.ElectionChainCodes.keySet()){
                JSONObject resp = FabricClient.query(client, channel, FabricConfig.ElectionChainCode(ek).getBallot(), "getVoteInviteStatistic", null);
                if (resp.containsKey("ret") && !resp.getBooleanValue("ret")) {
                    ret.put("ret", false);
                    ret.put("response", resp);
                    break;
                } else {
                    if(resp.containsKey("data")){
                        JSONObject objects = new JSONObject();
                        objects.put("electionKey",ek);
                        objects.put("data",resp.getJSONObject("data"));
                        ja.add(objects);
                    }
                }
            }
            if(!ret.containsKey("ret")){
                ret.put("ret", true);
                ret.put("response", ja);
            }
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return ret.toJSONString();
    }
}
