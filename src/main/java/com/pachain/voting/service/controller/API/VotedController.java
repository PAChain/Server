package com.pachain.voting.service.controller.API;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.pachain.voting.service.common.ECCUtils;
import com.pachain.voting.service.common.GlobalUtils;
import com.pachain.voting.service.common.RequestParams;
import com.pachain.voting.service.entities.modules.VoteDetail;
import com.pachain.voting.service.entities.modules.VoteResult;
import com.pachain.voting.service.entities.modules.VoteResultStatistics;
import com.pachain.voting.service.entities.modules.Voter;
import com.pachain.voting.service.entities.services.QueryParams;
import com.pachain.voting.service.entities.services.VoteDetailService;
import com.pachain.voting.service.entities.services.VoteResultService;
import com.pachain.voting.service.entities.services.VoterService;
import com.pachain.voting.service.fabric.FabricClient;
import com.pachain.voting.service.fabric.FabricConfig;
import com.pachain.voting.service.fabric.PeerAdmin;
import com.pachain.voting.service.fabric.WalletClient;
import com.pachain.voting.service.fabric.config.ChainCodeConfig;
import org.hyperledger.fabric.gateway.X509Identity;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.Peer;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@RestController
@RequestMapping("/api/voted")
public class VotedController {
    @Autowired
    private VoterService voterService;
    @Autowired
    private VoteDetailService voteDetailService;
    @Autowired
    private VoteResultService voteResultService;
    private static Logger logger = org.slf4j.LoggerFactory.getLogger(VotedController.class);

        @RequestMapping(value = "/getdecodevoted",method = RequestMethod.POST)
    public String getDecodeVoted(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String electionKey="";
        String token="";
        String publicKey="";
        boolean walletKey=true;
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            electionKey = requestParams.getString("electionkey", "");
            token = requestParams.getString("token", "");
            publicKey = requestParams.getString("publickey", "");
            walletKey = requestParams.getBoolean("walletKey", true);
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        try{
            if(walletKey){
                X509Identity user=WalletClient.GetIdentity(token,publicKey);
                if(user==null){
                    ret.put("ret", false);
                    ret.put("error", "publicKey not matched");
                    return ret.toJSONString();
                }
            }
            ChainCodeConfig chainCode = FabricConfig.ElectionChainCode(electionKey);
            HFClient client = FabricClient.getClient();
            client.setUserContext(new PeerAdmin(FabricConfig.FirstOrganization().getName()));
            Channel channel = FabricClient.getChannel(client, FabricConfig.Channel.getName());
            channel.addPeer(FabricClient.getFirstPeer(client));
            channel.initialize();
            JSONObject resp = FabricClient.query(client, channel, chainCode.getVoted(), "getDeCodeVoted", publicKey);
            boolean tmpRet=resp.containsKey("ret")?resp.getBoolean("ret"):false;
            JSONArray tmpJA = resp.containsKey("data")?resp.getJSONArray("data"):null;
            logger.info(GlobalUtils.getCurrentRequestPrefix()+"pk: "+publicKey+", data: "+(tmpJA!=null?tmpJA.size():"null"));
            ret.put("ret", tmpRet);
            ret.put("response", resp);
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return ret.toJSONString();
    }

    @RequestMapping(value = "/setdecodevoted",method = RequestMethod.POST)
    public String setDecodeVoted(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String electionKey="";
        String token="";
        String onionkey="";
        String votingnumber="";
        String county="";
        String packages="";
        String encodekey="";
        boolean walletKey=true;
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            electionKey = requestParams.getString("electionkey", "");
            token = requestParams.getString("token", "");
            onionkey = requestParams.getString("onionkey", "");
            votingnumber = requestParams.getString("votingnumber", "");
            county = requestParams.getString("county", "");
            packages = requestParams.getString("packages", "");
            encodekey = requestParams.getString("encodekey", "");
            walletKey = requestParams.getBoolean("walletKey", true);
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        try{
            Base64.Encoder encoder = Base64.getEncoder();
            Base64.Decoder decoder = Base64.getDecoder();
            if(walletKey){
                X509Identity user=WalletClient.GetIdentity(token,encodekey);
                if(user==null){
                    ret.put("ret", false);
                    ret.put("error", "publicKey not matched");
                    return ret.toJSONString();
                }
                else{
                    logger.info(GlobalUtils.getCurrentRequestPrefix()+"packages>>>>"+DateTime.now().toString("yyyy-MM-dd HH:mm:ss")+">>>>");
                    logger.info(GlobalUtils.getCurrentRequestPrefix()+"packages>>>>encodekey>>>>"+encodekey);
                    logger.info(GlobalUtils.getCurrentRequestPrefix()+"packages>>>>votingnumber>>>>"+votingnumber);
                    logger.info(GlobalUtils.getCurrentRequestPrefix()+"packages>>>>before>>>>"+packages);
                    packages=new String(ECCUtils.decrypt( decoder.decode(packages),(ECPrivateKey) user.getPrivateKey()),StandardCharsets.UTF_8);
                    logger.info(GlobalUtils.getCurrentRequestPrefix()+"packages>>>>after>>>>"+packages);
                }
            }
            else{
                logger.info(GlobalUtils.getCurrentRequestPrefix()+"packages>>>>"+packages);
            }
            JSONObject parseObj = (JSONObject)JSONObject.parse(packages);
            if(parseObj.containsKey("package")){
                packages=parseObj.getString("package");
            }
            ChainCodeConfig chainCode = FabricConfig.ElectionChainCode(electionKey);
            HFClient client = FabricClient.getClient();
            client.setUserContext(new PeerAdmin(FabricConfig.FirstOrganization().getName()));
            Channel channel = FabricClient.getChannel(client, FabricConfig.Channel.getName());
            List<Peer> endorsePeers = FabricClient.getEndorsePeers(client,chainCode.getEndorsement());
            for(Peer p:endorsePeers){
                channel.addPeer(p);
            }
            channel.initialize();
            JSONObject jo=new JSONObject();
            jo.put("votingnumber",votingnumber);
            jo.put("county",county);
            jo.put("onionkey",onionkey);
            jo.put("packages",packages);
            jo.put("encodekey",encodekey);
            JSONObject resp = FabricClient.invoke(client, channel, chainCode.getVoted(), "setDeCodeVoted", jo.toJSONString());
            ret.put("ret", resp.containsKey("ret")?resp.getBoolean("ret"):false);
            ret.put("response", resp);
            if(!parseObj.containsKey("package")){
                try{
                    int exists = voterService.checkVotingNumber(votingnumber);
                    if(exists<=0){
                        String verificationCode = parseObj.getString("verificationCode");
                        String key = parseObj.getString("key");
                        String state = parseObj.getString("state");
                        String tmpCounty = parseObj.getString("county");
                        String precinctNumber = parseObj.getString("precinctNumber");
                        Date votingDate = parseObj.getDate("votingDate");
                        JSONArray ja=parseObj.getJSONArray("votingData");
                        if(ja.size()>0){
                            for(int x=0;x<ja.size();x++){
                                JSONObject o = (JSONObject)ja.get(x);
                                Integer electionID = o.getInteger("electionID");
                                Integer seatID = o.getInteger("seatID");
                                JSONArray candidates = o.getJSONArray("candidates");
                                if(candidates.size()>0){
                                    for(int y=0;y<candidates.size();y++){
                                        JSONObject jsonObject = candidates.getJSONObject(y);
                                        voterService.votedResult(chainCode.getVoted(),
                                                resp.getString("txid"),
                                                votingnumber,verificationCode,key,state,tmpCounty,precinctNumber,
                                                electionID,seatID,jsonObject.getInteger("id"),jsonObject.getString("name"),votingDate);
                                    }
                                }
                            }
                        }
                    }
                }catch (Exception ex){
                    logger.error(ex.getMessage(),ex);
                }
                ret.put("ret",true);
            }
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return ret.toJSONString();
    }

    @RequestMapping(value = "/startdecodevoted",method = RequestMethod.POST)
    public String StartDecodeVoted(@RequestParam("params") String params){
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
            else{
                ChainCodeConfig chainCode = FabricConfig.ElectionChainCode(electionKey);
                HFClient client = FabricClient.getClient();
                client.setUserContext(WalletClient.GetUser(voter.getWalletID()));
                Channel channel = FabricClient.getChannel(client, FabricConfig.Channel.getName());
                List<Peer> endorsePeers = FabricClient.getEndorsePeers(client,chainCode.getEndorsement());
                for(Peer p:endorsePeers){
                    channel.addPeer(p);
                }
                channel.initialize();
                JSONObject resp = FabricClient.invoke(client, channel, chainCode.getVoted(), "startDecodeVoted", null);
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

    @RequestMapping(value = "/getdecodevodedstatus",method = RequestMethod.POST)
    public String GetDeCodeVodedStatus(@RequestParam("params") String params){
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
                JSONObject resp = FabricClient.invoke(client, channel, chainCode.getVoted(), "getDeCodeVodedStatus", null);
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

    @RequestMapping(value = "/vote",method = RequestMethod.POST)
    public String Vote(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String electionKey="";
        String votingDate="";
        String ballotNumber="";
        int electionID=0;
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
                votingDate=requestParams.getString("votingDate","");
                ballotNumber=requestParams.getString("ballotNumber","");
                electionID=requestParams.getInt("electionID",0);
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
                ChainCodeConfig chainCode = FabricConfig.ElectionChainCode(electionKey);
                HFClient client = FabricClient.getClient();
                client.setUserContext(WalletClient.GetUser(voter.getWalletID()));
                Channel channel = FabricClient.getChannel(client, FabricConfig.Channel.getName());
                List<Peer> endorsePeers = FabricClient.getEndorsePeers(client,chainCode.getEndorsement());
                for(Peer p:endorsePeers){
                    channel.addPeer(p);
                }
                channel.initialize();
                String[] ps=new String[4];
                ps[0]=voter.getPublicKey();
                ps[1]=votingDate;
                ps[2]=ballotNumber;
                ps[3]=tmpParams;
                JSONObject resp = FabricClient.invoke(client, channel, chainCode.getVoted(), "vote", ps);
                if (resp.containsKey("ret") && !resp.getBoolean("ret")) {
                    ret.put("ret", false);
                    ret.put("invoke", resp);
                } else {
                    ret.put("ret",true);
                    String response = resp.toJSONString();
                    ret.put("response", GlobalUtils.encryptData(voter.getKeyType(),voter.getEncryptKey(),response));
                    try{
                        voterService.voted(chainCode.getVoted(),resp.getString("txid"), voter.getPublicKey(),ballotNumber,electionID,DateTime.parse(votingDate).toDate());
                    }catch (Exception ex){
                        logger.error(GlobalUtils.getException(ex));
                    }
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

    @RequestMapping(value = "/confirmvoted",method = RequestMethod.POST)
    public String ConfirmVoted(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String electionKey="";
        String verifiedDate="";
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
                verifiedDate=requestParams.getString("verifiedDate","");
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
                List<Peer> endorsePeers = FabricClient.getEndorsePeers(client,chainCode.getEndorsement());
                for(Peer p:endorsePeers){
                    channel.addPeer(p);
                }
                channel.initialize();
                String[] ps=new String[2];
                ps[0]=voter.getPublicKey();
                ps[1]=verifiedDate;
                JSONObject resp = FabricClient.invoke(client, channel, chainCode.getBallot(), "confirmVoted", ps);
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

    @RequestMapping(value = "/querydecodevoted",method = RequestMethod.POST)
    public String QueryDecodeVoted(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String electionKey="";
        String userkey="";
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
                userkey=requestParams.getString("userkey","");
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
                JSONObject resp = FabricClient.query(client, channel, chainCode.getVoted(), "queryDeCodeVotedByUserKey", userkey);
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

    @RequestMapping(value = "/queryvoted",method = RequestMethod.POST)
    public String QueryVoted(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String electionKey="";
        String state="";
        String county="";
        String precinctNumber="";
        String ballotNumber="";
        String startStr="";
        String endStr="";
        int limit=10;
        int offset=0;
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            electionKey = requestParams.getString("electionKey", "");
            state = requestParams.getString("state", "");
            county = requestParams.getString("county", "");
            precinctNumber = requestParams.getString("precinctNumber", "");
            ballotNumber = requestParams.getString("ballotNumber", "");
            startStr = requestParams.getString("start", "");
            endStr = requestParams.getString("end", "");
            limit = requestParams.getInt("limit", 10);
            offset = requestParams.getInt("offset", 0);
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        try{
            String dateStr="";
            if(startStr!=null && !startStr.isEmpty() && endStr!=null &&!endStr.isEmpty()){
                dateStr="";
            }
            else if(startStr!=null && !startStr.isEmpty()){
                dateStr=startStr;
                startStr="";
            }
            else if(endStr!=null && !endStr.isEmpty()){
                dateStr=endStr;
                endStr="";
            }
            QueryParams queryParams = new QueryParams();
            queryParams.setState(state);
            queryParams.setCounty(county);
            queryParams.setPrecinctNumber(precinctNumber);
            queryParams.setBallotNumber(ballotNumber);
            queryParams.setDate(dateStr);
            queryParams.setStart(startStr);
            queryParams.setEnd(endStr);
            queryParams.setOffset(offset);
            queryParams.setLimit(limit);
            queryParams.setCount(0);
            ChainCodeConfig chainCode = FabricConfig.ElectionChainCode(electionKey);
            final List<VoteDetail> voteDetails = voteDetailService.queryVoted(chainCode.getVoted(),queryParams);
            ret.put("ret",true);
            JSONObject js=new JSONObject();
            js.put("count",queryParams.getCount());
            js.put("data",voteDetails);
            ret.put("response", js);
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return ret.toJSONString();
    }

    @RequestMapping(value = "/queryvoteresult",method = RequestMethod.POST)
    public String QueryVoteResult(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String electionKey="";
        String state="";
        String county="";
        String precinctNumber="";
        int seatID=0;
        String startStr="";
        String endStr="";
        int limit=10;
        int offset=0;
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            electionKey = requestParams.getString("electionKey", "");
            state = requestParams.getString("state", "");
            county = requestParams.getString("county", "");
            precinctNumber = requestParams.getString("precinctNumber", "");
            seatID = requestParams.getInt("seatID", 0);
            startStr = requestParams.getString("start", "");
            endStr = requestParams.getString("end", "");
            limit = requestParams.getInt("limit", 10);
            offset = requestParams.getInt("offset", 0);
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        try{
            String dateStr="";
            if(startStr!=null && !startStr.isEmpty() && endStr!=null &&!endStr.isEmpty()){
                dateStr="";
            }
            else if(startStr!=null && !startStr.isEmpty()){
                dateStr=startStr;
                startStr="";
            }
            else if(endStr!=null && !endStr.isEmpty()){
                dateStr=endStr;
                endStr="";
            }
            QueryParams queryParams = new QueryParams();
            queryParams.setState(state);
            queryParams.setCounty(county);
            queryParams.setPrecinctNumber(precinctNumber);
            queryParams.setSeatID(seatID);
            queryParams.setDate(dateStr);
            queryParams.setStart(startStr);
            queryParams.setEnd(endStr);
            queryParams.setOffset(offset);
            queryParams.setLimit(limit);
            queryParams.setCount(0);
            ChainCodeConfig chainCode = FabricConfig.ElectionChainCode(electionKey);
            final List<VoteResult> voteDetails = voteResultService.queryVoteResult(chainCode.getVoted(),queryParams);
            ret.put("ret",true);
            JSONObject js=new JSONObject();
            js.put("count",queryParams.getCount());
            js.put("data",voteDetails);
            ret.put("response", js);
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return ret.toJSONString();
    }

    @RequestMapping(value = "/getvoteresult",method = RequestMethod.POST)
    public String GetVoteResult(@RequestParam("params") String params){
        JSONObject ret=new JSONObject();
        String electionKey="";
        int electionID=0;
        String state="";
        String county="";
        String precinctNumber="";
        try {
            RequestParams requestParams = GlobalUtils.getParams(params);
            electionKey = requestParams.getString("electionKey", "");
            electionID = requestParams.getInt("electionID", 0);
            state = requestParams.getString("state", "");
            county = requestParams.getString("county", "");
            precinctNumber = requestParams.getString("precinctNumber", "");
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        try{
            QueryParams queryParams = new QueryParams();
            queryParams.setElectionID(electionID);
            queryParams.setState(state);
            queryParams.setCounty(county);
            queryParams.setPrecinctNumber(precinctNumber);
            queryParams.setCount(0);
            ChainCodeConfig chainCode = FabricConfig.ElectionChainCode(electionKey);
            final List<VoteResult> voteDetails = voteResultService.getVoteResult(chainCode.getVoted(),queryParams);
            final List<VoteResultStatistics> statistics = queryParams.getStatistics();
            ret.put("ret",true);
            JSONObject js=new JSONObject();
            if(statistics!=null && statistics.size()>0){
                VoteResultStatistics vr = statistics.get(0);
                js.put("voteCount",vr.getVoteCount());
                js.put("votedCount",vr.getVotedCount());
                js.put("percent",vr.getPercent());
                js.put("latedVoteDate",vr.getLatedVoteDate());
                js.put("latedVotedDate",vr.getLatedVotedDate());
            }
            JSONArray ja=new JSONArray();
            if(voteDetails!=null){
                for(VoteResult rt: voteDetails){
                    JSONObject to=new JSONObject();
                    to.put("electionID",rt.getElectionID());
                    to.put("seatID",rt.getSeatID());
                    to.put("candidateID",rt.getCandidateID());
                    to.put("count",rt.getCount());
                    to.put("percent",rt.getPercent());
                    ja.add(to);
                }
            }
            js.put("data",ja);

            try{
                String fn="candidates";
                if(state!=null && state.length()>0){
                    fn=fn+"\\"+state;
                    if(county!=null && county.length()>0){
                        fn=fn+"\\"+county;
                        if(precinctNumber!=null && precinctNumber.length()>0){
                            fn=fn+"\\"+precinctNumber;
                        }
                    }
                    fn=fn+"\\index.json";
                }
                else{
                    fn=fn+"\\index.json";
                }
                String resourcePath = new DefaultResourceLoader().getResource("").getFile().getPath();
                resourcePath = resourcePath.substring(0,resourcePath.indexOf("WEB-INF"))+fn;
                logger.error("Check File: "+resourcePath);
                final File candidates = Paths.get(resourcePath).toFile();
                if(candidates.exists() && candidates.isFile()){
                    logger.error("Open File: "+resourcePath);
                    InputStream inputStream=null;
                    InputStreamReader reader=null;
                    BufferedReader br=null;
                    String content = "";
                    try {
                        inputStream = new FileInputStream(candidates);
                        reader = new InputStreamReader(inputStream,"UTF-8");
                        br = new BufferedReader(reader);
                        String s = "";
                        while ((s = br.readLine()) != null)
                            content = content + s;
                    }catch (Exception ex){
                        logger.error("Open File Failed: "+resourcePath+"\n"+ex.getMessage());
                    }
                    finally {
                        try {
                            if (br != null) {
                                br.close();
                            }
                        }catch (Exception ex){}
                        try {
                            if (reader != null) {
                                reader.close();
                            }
                        }catch (Exception ex){}
                        try {
                            if(inputStream!=null){
                                inputStream.close();
                            }
                        }catch (Exception ex){}
                    }
                    if(content.length()>0){
                        try {
                            JSONArray jca = JSONArray.parseArray(content);
                            js.put("candidates", jca);
                        }catch (Exception ex){
                            logger.error("Convert To Json  Failed: "+resourcePath+"\n"+ex.getMessage());
                        }
                    }
                }
            }catch (Exception ex){}
            ret.put("response", js);
        }
        catch (Exception ex){
            ret.put("ret",false);
            ret.put("error",ex.getMessage());
            logger.error(GlobalUtils.getException(ex));
        }
        return ret.toJSONString();
    }
}
