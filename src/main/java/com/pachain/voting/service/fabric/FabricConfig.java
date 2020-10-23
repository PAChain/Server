package com.pachain.voting.service.fabric;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.pachain.voting.service.common.GlobalUtils;
import com.pachain.voting.service.fabric.config.*;
import org.slf4j.Logger;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

@Component
public class FabricConfig {
    public static com.pachain.voting.service.fabric.config.ChannelConfig Channel;
    public static ChainCodeConfig VoterChainCode;
    public static Map<String,ChainCodeConfig> ElectionChainCodes;
    public static Map<String,OrderConfig> Orders;
    public static Map<String,OrganizationConfig> Organizations;
    public static Map<String, CAConfig> CAS;
    private static int PeerCount=0;

    private static Logger logger = org.slf4j.LoggerFactory.getLogger(FabricConfig.class);

    public  static int getPeerCount(){return  PeerCount;}

    public static OrderConfig FirstOrder() {
        OrderConfig obj = null;
        for (Map.Entry<String, OrderConfig> entry : Orders.entrySet()) {
            obj = entry.getValue();
            if (obj != null) {
                break;
            }
        }
        return  obj;
    }
    public static OrganizationConfig FirstOrganization() {
        OrganizationConfig obj = null;
        for (Map.Entry<String, OrganizationConfig> entry : Organizations.entrySet()) {
            obj = entry.getValue();
            if (obj != null) {
                break;
            }
        }
        return  obj;
    }
    public static ChainCodeConfig LastedElectionChainCode() {
        ChainCodeConfig chain = null;
        for (Map.Entry<String, ChainCodeConfig> entry : ElectionChainCodes.entrySet()) {
            ChainCodeConfig obj = entry.getValue();
            if (obj != null) {
                chain=obj;
            }
        }
        return  chain;
    }
    public static ChainCodeConfig ElectionChainCode(String name) {
        if(name==null || name.isEmpty() || name.length()==0){
            return LastedElectionChainCode();
        }
        if(ElectionChainCodes.containsKey(name)){
            ChainCodeConfig obj = ElectionChainCodes.get(name);
            if (obj != null) {
                 return obj;
            }
        }
        return  null;
    }

    @PostConstruct
    public void init(){
        try{
            DefaultResourceLoader resourceLoader = new DefaultResourceLoader();
            Resource resource = resourceLoader.getResource("classpath:FabricConfig.json");
            InputStream inputStream = resource.getInputStream();
            BufferedReader br=new BufferedReader(new InputStreamReader(inputStream));
            String js="";
            String s="";
            while((s=br.readLine())!=null)
                js=js+s;
            br.close();
            inputStream.close();
            JSONObject parse = (JSONObject)JSONObject.parse(js);
            FabricConfig.Channel=new ChannelConfig();
            FabricConfig.VoterChainCode=new ChainCodeConfig();
            FabricConfig.ElectionChainCodes =new HashMap<String,ChainCodeConfig>();
            FabricConfig.Orders=new HashMap<>();
            FabricConfig.Organizations=new HashMap<>();
            FabricConfig.CAS=new HashMap<String,CAConfig>();
            FabricConfig.Channel.setName(parse.getString("channel"));

            JSONObject chaincode = parse.getJSONObject("chaincode");
            if(chaincode!=null){
                FabricConfig.VoterChainCode.setVoter(chaincode.getString("voter"));
                FabricConfig.VoterChainCode.setEndorsement(chaincode.getString("endorsement"));
                JSONArray elections = chaincode.getJSONArray("elections");
                if(elections!=null){
                    for (int x = 0; x < elections.size(); x++){
                        JSONObject jo= (JSONObject)elections.get(x);
                        ChainCodeConfig cc=new ChainCodeConfig();
                        cc.setName(jo.getString("name"));
                        cc.setVoted(jo.getString("voted"));
                        cc.setBallot(jo.getString("ballot"));
                        cc.setEndorsement(jo.getString("endorsement"));
                        if(!FabricConfig.ElectionChainCodes.containsKey(cc.getName())){
                            FabricConfig.ElectionChainCodes.put(cc.getName(),cc);
                        }
                    }
                }
            }
            JSONArray ja = (JSONArray) parse.getJSONArray("orders");
            if(ja!=null){
                for (int x = 0; x < ja.size(); x++){
                    JSONObject jo= (JSONObject)ja.get(x);
                    OrderConfig cc=new OrderConfig();
                    cc.setName(jo.getString("name"));
                    cc.setUrl(jo.getString("url"));
                    cc.setTlsCACertFile(jo.getString("tlsCACertFile"));
                    if(!FabricConfig.Orders.containsKey(cc.getName())){
                        FabricConfig.Orders.put(cc.getName(),cc);
                    }
                }
            }
            ja = (JSONArray) parse.getJSONArray("certificateAuthorities");
            if(ja!=null){
                for (int x = 0; x < ja.size(); x++){
                    JSONObject jo= (JSONObject)ja.get(x);
                    CAConfig cc=new CAConfig();
                    cc.setName(jo.getString("name"));
                    cc.setUrl(jo.getString("url"));
                    cc.setCertFile(jo.getString("certFile"));
                    if(!FabricConfig.CAS.containsKey(cc.getName())){
                        FabricConfig.CAS.put(cc.getName(),cc);
                    }
                }
            }
            PeerCount=0;
            ja = (JSONArray) parse.getJSONArray("organizations");
            if(ja!=null){
                for (int x = 0; x < ja.size(); x++){
                    JSONObject jo= (JSONObject)ja.get(x);
                    OrganizationConfig cc=new OrganizationConfig();
                    cc.setName(jo.getString("name"));
                    cc.setMSPID(jo.getString("mspid"));
                    cc.setAdminName(jo.getString("adminName"));
                    cc.setAdminKeyFile(jo.getString("adminKeyFile"));
                    cc.setAdminCertFile(jo.getString("adminCertFile"));
                    cc.setUserName(jo.getString("userName"));
                    cc.setUserKeyFile(jo.getString("userKeyFile"));
                    cc.setUserCertFile(jo.getString("userCertFile"));
                    String ca =jo.getString("ca");
                    if(FabricConfig.CAS.containsKey(ca)){
                        cc.setCa(FabricConfig.CAS.get(ca));
                    }
                    Map<String, PeerConfig> mps = new HashMap<String, PeerConfig>();
                    JSONArray peers = (JSONArray) jo.getJSONArray("peers");
                    if(peers!=null){
                        for(int y=0;y<peers.size();y++){
                            JSONObject jp= (JSONObject)peers.get(y);
                            PeerConfig pc=new PeerConfig();
                            pc.setName(jp.getString("name"));
                            pc.setUrl(jp.getString("url"));
                            pc.setTlsCACertFile(jp.getString("tlsCACertFile"));
                            pc.setTlsClientKeyFile(jp.getString("tlsClientKeyFile"));
                            pc.setTlsClientCertFile(jp.getString("tlsClientCertFile"));
                            if(!mps.containsKey(cc.getName())){
                                mps.put(pc.getName(),pc);
                                PeerCount++;
                            }
                        }
                    }
                    cc.setPeers(mps);
                    if(!FabricConfig.Organizations.containsKey(cc.getName())){
                        FabricConfig.Organizations.put(cc.getName(),cc);
                    }
                }
            }
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        logger.info(GlobalUtils.getCurrentRequestPrefix()+"loaded fabric config");
    }
}
