package com.pachain.voting.service.fabric;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.JSONObject;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.pachain.voting.service.common.GlobalUtils;
import com.pachain.voting.service.fabric.config.OrderConfig;
import com.pachain.voting.service.fabric.config.OrganizationConfig;
import com.pachain.voting.service.fabric.config.PeerConfig;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.CryptoException;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.ledger.rwset.Rwset;
import org.hyperledger.fabric.protos.ledger.rwset.kvrwset.KvRwset;
import org.hyperledger.fabric.protos.peer.ProposalPackage;
import org.hyperledger.fabric.protos.peer.ProposalResponsePackage;
import org.hyperledger.fabric.protos.peer.TransactionPackage;
import org.hyperledger.fabric.sdk.*;
import org.hyperledger.fabric.sdk.exception.ChaincodeCollectionConfigurationException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.slf4j.Logger;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Paths;
import java.security.Security;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.hyperledger.fabric.sdk.BlockInfo.EnvelopeType.TRANSACTION_ENVELOPE;

public class FabricClient {
    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    private static Logger logger = org.slf4j.LoggerFactory.getLogger(FabricClient.class);

    public static JSONObject getBlockInfo(BlockInfo blockInfo) throws IOException, InvalidArgumentException {
        JSONObject ret=new JSONObject();
        JSONArray jsArr=new JSONArray();
        ret.put("blockNumber",blockInfo.getBlockNumber());
        ret.put("envelopCount",blockInfo.getEnvelopeCount());
        for (BlockInfo.EnvelopeInfo envelopeInfo : blockInfo.getEnvelopeInfos()) {
            JSONObject tmp1=new JSONObject();
            tmp1.put("creatorID",envelopeInfo.getCreator().getId());
            tmp1.put("creatorMSPID",envelopeInfo.getCreator().getMspid());
            tmp1.put("nonce",Hex.encodeHexString(envelopeInfo.getNonce()));
            tmp1.put("txid",envelopeInfo.getTransactionID());
            tmp1.put("channelId",envelopeInfo.getChannelId());
            tmp1.put("timestamp", envelopeInfo.getTimestamp());
            tmp1.put("type",envelopeInfo.getType());
            if (envelopeInfo.getType() == TRANSACTION_ENVELOPE) {
                JSONObject tmp2=new JSONObject();
                BlockInfo.TransactionEnvelopeInfo transactionEnvelopeInfo = (BlockInfo.TransactionEnvelopeInfo) envelopeInfo;
                tmp2.put("isValid",transactionEnvelopeInfo.isValid());
                tmp2.put("validationCode",transactionEnvelopeInfo.getValidationCode());
                JSONArray tmpArr2=new JSONArray();
                for (BlockInfo.TransactionEnvelopeInfo.TransactionActionInfo transactionActionInfo : transactionEnvelopeInfo.getTransactionActionInfos()) {
                    try{
                        tmpArr2.add(getTransactionEnvelopeInfo(transactionActionInfo));
                    }
                    catch (Exception ex){}
                }
                tmp2.put("actions",tmpArr2);
                tmp1.put("transaction",tmp2);
            }
            jsArr.add(tmp1);
        }
        ret.put("envelopes",jsArr);
        return ret;
    }
    public static JSONArray getTransactionInfo(TransactionInfo txInfo) throws InvalidProtocolBufferException {
        Common.Envelope envelope = txInfo.getEnvelope();
        Common.Payload payload = Common.Payload.parseFrom(envelope.getPayload());
        TransactionPackage.Transaction transaction = TransactionPackage.Transaction.parseFrom(payload.getData());
        TransactionPackage.TransactionAction action = transaction.getActionsList().get(0); // 0 is a index
        TransactionPackage.ChaincodeActionPayload chaincodeActionPayload = TransactionPackage.ChaincodeActionPayload.parseFrom(action.getPayload());
        ProposalResponsePackage.ProposalResponsePayload prp = ProposalResponsePackage.ProposalResponsePayload.parseFrom(chaincodeActionPayload.getAction().getProposalResponsePayload());
        ProposalPackage.ChaincodeAction ca = ProposalPackage.ChaincodeAction.parseFrom(prp.getExtension());
        JSONArray ret=new JSONArray();
        try {
            Rwset.TxReadWriteSet txrws = Rwset.TxReadWriteSet.parseFrom(ca.getResults());
            TxReadWriteSetInfo rwsetInfo = new TxReadWriteSetInfo(txrws);
            if (null != rwsetInfo) {
                for (TxReadWriteSetInfo.NsRwsetInfo nsRwsetInfo : rwsetInfo.getNsRwsetInfos()) {
                    final String namespace = nsRwsetInfo.getNamespace();
                    KvRwset.KVRWSet rws = nsRwsetInfo.getRwset();
                    JSONObject tmp2=new JSONObject();
                    JSONArray tmpArr2=new JSONArray();
                    for (KvRwset.KVRead readList : rws.getReadsList()) {
                        JSONObject tmp3=new JSONObject();
                        tmp3.put("key",readList.getKey());
                        tmp3.put("blockNumber", readList.getVersion().getBlockNum());
                        tmp3.put("txNumber", readList.getVersion().getTxNum());
                        tmpArr2.add(tmp3);
                    }
                    tmp2.put("reads",tmpArr2);
                    tmpArr2=new JSONArray();
                    for (KvRwset.KVWrite writeList : rws.getWritesList()) {
                        JSONObject tmp3=new JSONObject();
                        tmp3.put("key",writeList.getKey());
                        tmp3.put("value",writeList.getValue().toStringUtf8());
                        tmpArr2.add(tmp3);
                    }
                    tmp2.put("writes",tmpArr2);
                    tmp2.put("namespace",namespace);
                    ret.add(tmp2);
                }
            }
        }catch (Exception e){
            System.out.println("Error: "+e.getMessage());
        }
        return  ret;
    }
    public  static JSONObject getTransactionEnvelopeInfo(BlockInfo.TransactionEnvelopeInfo.TransactionActionInfo transactionActionInfo) throws InvalidProtocolBufferException {
        JSONObject ret=new JSONObject();
        JSONArray jarr=new JSONArray();
        for (int n = 0; n < transactionActionInfo.getEndorsementsCount(); ++n) {
            BlockInfo.EndorserInfo endorserInfo = transactionActionInfo.getEndorsementInfo(n);
            JSONObject tmp1=new JSONObject();
            tmp1.put("signature",Hex.encodeHexString(endorserInfo.getSignature()));
            tmp1.put("Mspid",endorserInfo.getMspid());
            tmp1.put("Id",endorserInfo.getId());
            jarr.add(tmp1);
        }
        ret.put("endorsers",jarr);
        jarr=new JSONArray();
        for (int z = 0; z < transactionActionInfo.getChaincodeInputArgsCount(); ++z) {
            JSONObject tmp1=new JSONObject();
            tmp1.put("order",z);
            tmp1.put("args",transactionActionInfo.getChaincodeInputArgs(z));
            jarr.add(tmp1);
        }
        ret.put("inputArgs",jarr);
        ret.put("status",transactionActionInfo.getProposalResponseStatus());
        TxReadWriteSetInfo rwsetInfo = transactionActionInfo.getTxReadWriteSet();
        if (null != rwsetInfo) {
            JSONArray tmpArr1=new JSONArray();
            for (TxReadWriteSetInfo.NsRwsetInfo nsRwsetInfo : rwsetInfo.getNsRwsetInfos()) {
                final String namespace = nsRwsetInfo.getNamespace();
                KvRwset.KVRWSet rws = nsRwsetInfo.getRwset();
                JSONObject tmp2=new JSONObject();
                JSONArray tmpArr2=new JSONArray();
                for (KvRwset.KVRead readList : rws.getReadsList()) {
                    JSONObject tmp3=new JSONObject();
                    tmp3.put("key",readList.getKey());
                    tmp3.put("blockNumber", readList.getVersion().getBlockNum());
                    tmp3.put("txNumber", readList.getVersion().getTxNum());
                    tmpArr2.add(tmp3);
                }
                tmp2.put("reads",tmpArr2);
                tmpArr2=new JSONArray();
                for (KvRwset.KVWrite writeList : rws.getWritesList()) {
                    JSONObject tmp3=new JSONObject();
                    tmp3.put("key",writeList.getKey());
                    tmp3.put("value",writeList.getValue().toStringUtf8());
                    tmpArr2.add(tmp3);
                }
                tmp2.put("writes",tmpArr2);
                tmpArr1.add(tmp2);
            }
            ret.put("rwSet",tmpArr1);
        }
        return ret;
    }
    public static JSONArray parseResponse(Collection<ProposalResponse> proposalResponses) {
        JSONArray ret = new JSONArray();
        Integer index=0;
        for (ProposalResponse response : proposalResponses) {
            ret.add(parseResponse(response));
        }
        return ret;
    }
    public static JSONObject parseResponse(ProposalResponse response) {
        ProposalResponsePackage.Response resp = response.getProposalResponse().getResponse();
        JSONObject jsonObject=new JSONObject();
        jsonObject.put("status", response.getStatus().getStatus());
        jsonObject.put("message",response.getMessage());
        jsonObject.put("isVerified", response.isVerified());
        jsonObject.put("peer", response.getPeer().toString());
        jsonObject.put("txid", response.getTransactionID());
        jsonObject.put("response",parseResponse(resp));
        return jsonObject;
    }
    public static JSONObject parseResponse(ProposalResponsePackage.Response response){
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("status", response.getStatus());
        jsonObject.put("message",response.getMessage());
        String payload = response.getPayload().toStringUtf8();
        jsonObject.put("payload", parsePayload(payload));
        return jsonObject;
    }
    public static Object parsePayload(String result) {
        JSONObject jsonObject = new JSONObject();
        int jsonVerify = isJSONValid(result);
        switch (jsonVerify) {
            case 0:
                jsonObject.put("payload", result);
                break;
            case 1:
                return JSONObject.parseObject(result);
            case 2:
                return JSONObject.parseArray(result);
        }
        return jsonObject;
    }
    public static int isJSONValid(String str) {
        try {
            JSONObject.parseObject(str);
            return 1;
        } catch (JSONException ex) {
            try {
                JSONObject.parseArray(str);
                return 2;
            } catch (JSONException ex1) {
                return 0;
            }
        }
    }
    public static HFClient getClient() throws CryptoException, InvalidArgumentException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException, org.hyperledger.fabric.sdk.exception.CryptoException {
        HFClient client = HFClient.createNewInstance();
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        return client;
    }
    public static Orderer getFirstOrderer(HFClient client) throws InvalidArgumentException {
        Properties orderer1Prop = new Properties();
        OrderConfig orderConfig = FabricConfig.FirstOrder();
        orderer1Prop.setProperty("pemFile", orderConfig.getTlsCACertFile());
        orderer1Prop.setProperty("sslProvider", "openSSL");
        orderer1Prop.setProperty("negotiationType", "TLS");
        orderer1Prop.setProperty("hostnameOverride", orderConfig.getName());
        orderer1Prop.setProperty("trustServerCertificate", "true");
        Orderer orderer = client.newOrderer(orderConfig.getName() , orderConfig.getUrl(), orderer1Prop);
        return orderer;
    }
    public static Peer getPeer(HFClient client,PeerConfig peer) throws InvalidArgumentException {
        Properties peerProp = new Properties();
        peerProp.setProperty("pemFile", peer.getTlsCACertFile());
        peerProp.setProperty("sslProvider", "openSSL");
        peerProp.setProperty("negotiationType", "TLS");
        peerProp.setProperty("hostnameOverride", peer.getName());
        peerProp.setProperty("trustServerCertificate", "true");
        peerProp.setProperty("clientKeyFile", peer.getTlsClientKeyFile());
        peerProp.setProperty("clientCertFile", peer.getTlsClientCertFile());
        return client.newPeer(peer.getName(), peer.getUrl(), peerProp);
    }
    public static Peer getFirstPeer(HFClient client) throws InvalidArgumentException {
        return getPeer(client,FabricConfig.FirstOrganization().getFirstPeer());
    }
    /**
     *
     * @param client
     * @return
     * @throws InvalidArgumentException
     */
    public static List<Peer> getEndorsePeers(HFClient client, String rule) throws InvalidArgumentException {
        //Policy Rule: ANY、ALL、MAJORITY
        boolean any = rule.toLowerCase().equals("any");
        boolean all = rule.toLowerCase().equals("all");
        boolean majority = rule.toLowerCase().equals("majority");
        List<Peer> ret=new ArrayList<Peer>();
        int peerCount=0;
        for(OrganizationConfig org:FabricConfig.Organizations.values()){
            for(PeerConfig pc :org.getPeers().values()){
                ret.add(getPeer(client,pc));
                peerCount++;
                if(any){return  ret;}
                if(majority && peerCount*2>FabricConfig.getPeerCount()){return ret;}
            }
        }
        return  ret;
    }
    public static Channel getChannel(HFClient client, String channelName) throws InvalidArgumentException, TransactionException {
        //EventHub eventHub = client.newEventHub("peer1.operation.cmpay.com",Config.EVENTHUB1_ADDRESS,peer1Prop);
        Channel channel = client.newChannel(channelName);
        channel.addOrderer(getFirstOrderer(client));
        //channel.addEventHub(eventHub);
        return channel;
    }
    public static Channel createChannel(HFClient client, String channelName, String channelTxFile) throws InvalidArgumentException, TransactionException, IOException {
        ChannelConfiguration channelConfiguration = new ChannelConfiguration(Paths.get(channelTxFile).toFile());
        Channel channel = client.newChannel(channelName, getFirstOrderer(client), channelConfiguration, client.getChannelConfigurationSignature(channelConfiguration, client.getUserContext()));
        channel.initialize();
        return channel;
    }
    public static  void updateChannel(HFClient hfClient, String channelName, Orderer ordererName, byte[] txConBytes) throws InvalidArgumentException, TransactionException {
        Channel channel = hfClient.newChannel(channelName);
        channel.initialize();
        UpdateChannelConfiguration conCfg = new UpdateChannelConfiguration(txConBytes);
        byte[] signData = hfClient.getUpdateChannelConfigurationSignature(conCfg, hfClient.getUserContext());
        channel.updateChannelConfiguration(conCfg, signData);
    }
    public static String installChainCode(HFClient client, Channel channel, String chaincodeFile) throws InvalidArgumentException, ProposalException, IOException {
        LifecycleInstallChaincodeRequest lifecycleInstallChaincodeRequest = client.newLifecycleInstallChaincodeRequest();
        lifecycleInstallChaincodeRequest.setUserContext(new PeerAdmin(FabricConfig.FirstOrganization().getName()));
        lifecycleInstallChaincodeRequest.setLifecycleChaincodePackage(LifecycleChaincodePackage.fromFile(Paths.get(chaincodeFile).toFile()));
        Collection<Peer> peers = channel.getPeers();
        Collection<LifecycleInstallChaincodeProposalResponse> lifecycleInstallChaincodeProposalResponses = client.sendLifecycleInstallChaincodeRequest(lifecycleInstallChaincodeRequest, peers);
        Collection<ProposalResponse> successful = new LinkedList<>();
        Collection<ProposalResponse> failed = new LinkedList<>();
        String packageID = null;
        for (LifecycleInstallChaincodeProposalResponse response : lifecycleInstallChaincodeProposalResponses) {
            if (response.getStatus() == ProposalResponse.Status.SUCCESS) {
                //log.info("Successful install proposal response Txid: %s from peer %s", response.getTransactionID(), response.getPeer().getName());
                successful.add(response);
                if (packageID == null) {
                    packageID = response.getPackageId();
                    //assertNotNull(format("Hashcode came back as null from peer: %s ", response.getPeer()), packageID);
                } else {
                    //assertEquals("Miss match on what the peers returned back as the packageID", packageID, response.getPackageId());
                }
            } else {
                failed.add(response);
            }
        }
        if (failed.size() > 0) {
            ProposalResponse first = failed.iterator().next();
            //log.info("Not enough endorsers for install :" + successful.size() + ".  " + first.getMessage());
        }
        //assertNotNull(packageID);
        //assertFalse(packageID.isEmpty());
        return packageID;
    }
    public static JSONObject queryInstalledChaincodes(HFClient client,Collection<Peer> peers) throws ProposalException, InvalidArgumentException {
        JSONObject jsonObject = new JSONObject();
        Collection<LifecycleQueryInstalledChaincodesProposalResponse> results = client.sendLifecycleQueryInstalledChaincodes(client.newLifecycleQueryInstalledChaincodesRequest(), peers);
        if(results!=null && results.size()>0){
            for (LifecycleQueryInstalledChaincodesProposalResponse result : results) {
                final String peerName = result.getPeer().getName();
                Collection<LifecycleQueryInstalledChaincodesProposalResponse.LifecycleQueryInstalledChaincodesResult> lifecycleQueryInstalledChaincodesResult = result.getLifecycleQueryInstalledChaincodesResult();
                jsonObject.put(peerName, lifecycleQueryInstalledChaincodesResult);
            }
        }
        return jsonObject;
    }
    public static JSONObject approveChaincode(HFClient client, Channel channel,String chaincodeName,
                                        String chaincodeVersion,String chaincodePackageID,
                                        LifecycleChaincodeEndorsementPolicy chaincodeEndorsementPolicy,
                                        ChaincodeCollectionConfiguration chaincodeCollectionConfiguration, boolean initRequired, Collection<Peer> orgPeers) throws InvalidArgumentException, ProposalException {
        JSONObject jsonObject = new JSONObject();
        long sequence = getSequence(chaincodeName, client, channel, orgPeers);
        //LifecycleChaincodeEndorsementPolicy chaincodeEndorsementPolicy = LifecycleChaincodeEndorsementPolicy.fromSignaturePolicyYamlFile(Paths.get(System.getenv(REST_CFG_PATH) + "/chaincodeendorsementpolicy.yaml"));
        //ChaincodeCollectionConfiguration chaincodeConfiguration = ChaincodeCollectionConfiguration.fromYamlFile(new File(System.getenv(REST_CFG_PATH) + "/PrivateDataIT.yaml"));
        //BlockEvent.TransactionEvent transactionEvent = lifecycleApproveChaincodeDefinitionForMyOrg(client, channel,
        //Collections.singleton(anOrg1Peer),  //support approve on multiple peers but really today only need one. Go with minimum.
        //sequence, chaincodeName, chaincodeVersion, chaincodeEndorsementPolicy, chaincodeConfiguration, false, orgChaincodePackageID)
        //.get(100100, TimeUnit.SECONDS);
        LifecycleApproveChaincodeDefinitionForMyOrgRequest lifecycleApproveChaincodeDefinitionForMyOrgRequest = client.newLifecycleApproveChaincodeDefinitionForMyOrgRequest();
        if(chaincodeName!=null && chaincodeName.length()>0){ lifecycleApproveChaincodeDefinitionForMyOrgRequest.setChaincodeName(chaincodeName); }
        if(chaincodeVersion!=null && chaincodeVersion.length()>0){lifecycleApproveChaincodeDefinitionForMyOrgRequest.setChaincodeVersion(chaincodeVersion);}
        if(chaincodeEndorsementPolicy!=null){lifecycleApproveChaincodeDefinitionForMyOrgRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);}
        if(chaincodeCollectionConfiguration!=null){lifecycleApproveChaincodeDefinitionForMyOrgRequest.setChaincodeCollectionConfiguration(chaincodeCollectionConfiguration);}
        lifecycleApproveChaincodeDefinitionForMyOrgRequest.setInitRequired(initRequired);
        if(chaincodePackageID!=null && chaincodePackageID.length()>0){lifecycleApproveChaincodeDefinitionForMyOrgRequest.setPackageId(chaincodePackageID);}
        lifecycleApproveChaincodeDefinitionForMyOrgRequest.setSequence(1);
        LifecycleApproveChaincodeDefinitionForMyOrgProposalResponse lifecycleApproveChaincodeDefinitionForMyOrgProposalResponse = channel.sendLifecycleApproveChaincodeDefinitionForMyOrgProposal(lifecycleApproveChaincodeDefinitionForMyOrgRequest, orgPeers.iterator().next());
        jsonObject.put(lifecycleApproveChaincodeDefinitionForMyOrgProposalResponse.getPeer().getName(),lifecycleApproveChaincodeDefinitionForMyOrgProposalResponse.getProposalResponse());
        return  jsonObject;
    }
    public static JSONObject checkCommitReadinessStatus(HFClient client, Channel channel,String chaincodeName,
                                                  String chaincodeVersion, LifecycleChaincodeEndorsementPolicy chaincodeEndorsementPolicy,
                                                  ChaincodeCollectionConfiguration chaincodeCollectionConfiguration, boolean initRequired, Collection<Peer> orgPeers) throws InvalidArgumentException, ProposalException {
        long sequence = getSequence(chaincodeName, client, channel, channel.getPeers());
        JSONObject array = new JSONObject();
        JSONObject approved = new JSONObject();
        JSONObject unApproved = new JSONObject();
        LifecycleCheckCommitReadinessRequest lifecycleCheckCommitReadinessRequest = client.newLifecycleSimulateCommitChaincodeDefinitionRequest();
        lifecycleCheckCommitReadinessRequest.setSequence(sequence);
        lifecycleCheckCommitReadinessRequest.setChaincodeName(chaincodeName);
        lifecycleCheckCommitReadinessRequest.setChaincodeVersion(chaincodeVersion);
        if (null != chaincodeEndorsementPolicy) {lifecycleCheckCommitReadinessRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);}
        if (null != chaincodeCollectionConfiguration) {lifecycleCheckCommitReadinessRequest.setChaincodeCollectionConfiguration(chaincodeCollectionConfiguration);}
        lifecycleCheckCommitReadinessRequest.setInitRequired(initRequired);
        Collection<LifecycleCheckCommitReadinessProposalResponse> lifecycleSimulateCommitChaincodeDefinitionProposalResponse = channel.sendLifecycleCheckCommitReadinessRequest(lifecycleCheckCommitReadinessRequest, orgPeers);
        for (LifecycleCheckCommitReadinessProposalResponse resp : lifecycleSimulateCommitChaincodeDefinitionProposalResponse) {
            final Peer peer = resp.getPeer();
            //assertEquals(ChaincodeResponse.Status.SUCCESS, resp.getStatus());
            // assertEquals(format("Approved orgs failed on %s", peer), expectedApproved, resp.getApprovedOrgs());
            //log.info(format("Approved orgs %s on %s", peer, resp.getApprovedOrgs()));
            approved.put(peer.getName(), resp.getApprovedOrgs());
            //assertEquals(format("UnApproved orgs failed on %s", peer), expectedUnApproved, resp.getUnApprovedOrgs());
            //log.info(format("UnApproved orgs %s on %s", peer, resp.getUnApprovedOrgs()));
            unApproved.put(peer.getName(), resp.getUnApprovedOrgs());
            //assertEquals(format("UnApproved orgs failed on %s", peer), expectedUnApproved, resp.getUnApprovedOrgs());
        }
        array.put("Approved", approved);
        array.put("UnApproved", unApproved);
        return array;
    }
    public static  void commitChaincode(HFClient client, Channel channel,String chaincodeName,
                                  String chaincodeVersion, LifecycleChaincodeEndorsementPolicy chaincodeEndorsementPolicy,
                                  ChaincodeCollectionConfiguration chaincodeCollectionConfiguration, boolean initRequired, Collection<Peer> orgPeers) throws InvalidArgumentException, ProposalException {
        long sequence = getSequence(chaincodeName, client, channel, channel.getPeers());
        LifecycleCommitChaincodeDefinitionRequest lifecycleCommitChaincodeDefinitionRequest = client.newLifecycleCommitChaincodeDefinitionRequest();
        lifecycleCommitChaincodeDefinitionRequest.setSequence(sequence);
        lifecycleCommitChaincodeDefinitionRequest.setChaincodeName(chaincodeName);
        lifecycleCommitChaincodeDefinitionRequest.setChaincodeVersion(chaincodeVersion);
        if (null != chaincodeEndorsementPolicy) {
            lifecycleCommitChaincodeDefinitionRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);
        }
        if (null != chaincodeCollectionConfiguration) {
            lifecycleCommitChaincodeDefinitionRequest.setChaincodeCollectionConfiguration(chaincodeCollectionConfiguration);
        }
        //Collection<Peer> orgOtherPeers = Util.addOtherOrgPeers(client, channel, peerDomain);
        //Collection<Peer> endorsingPeers = Arrays.asList(org1MyPeers.iterator().next(), orgOtherPeers.iterator().next());
        lifecycleCommitChaincodeDefinitionRequest.setInitRequired(initRequired);
        Collection<LifecycleCommitChaincodeDefinitionProposalResponse> lifecycleCommitChaincodeDefinitionProposalResponses = channel.sendLifecycleCommitChaincodeDefinitionProposal(lifecycleCommitChaincodeDefinitionRequest,orgPeers);
        for (LifecycleCommitChaincodeDefinitionProposalResponse resp : lifecycleCommitChaincodeDefinitionProposalResponses) {
            final Peer peer = resp.getPeer();
            //requested sequence is 1, but new definition must be sequence 2
            //assertEquals(format("%s had unexpected status.", peer.toString()), ChaincodeResponse.Status.SUCCESS, resp.getStatus());
            //assertTrue(format("%s not verified.", peer.toString()), resp.isVerified());
        }
        CompletableFuture<BlockEvent.TransactionEvent> transactionEvent = channel.sendTransaction(lifecycleCommitChaincodeDefinitionProposalResponses);
    }
    public static void queryChaincodeDefinition(HFClient client, Channel channel, String chaincodeName, Collection<Peer> peers, long expectedSequence, boolean expectedInitRequired, byte[] expectedValidationParameter,
                                                  ChaincodeCollectionConfiguration expectedChaincodeCollectionConfiguration) throws ProposalException, InvalidArgumentException, ChaincodeCollectionConfigurationException {
        final QueryLifecycleQueryChaincodeDefinitionRequest queryLifecycleQueryChaincodeDefinitionRequest = client.newQueryLifecycleQueryChaincodeDefinitionRequest();
        queryLifecycleQueryChaincodeDefinitionRequest.setChaincodeName(chaincodeName);
        Collection<LifecycleQueryChaincodeDefinitionProposalResponse> queryChaincodeDefinitionProposalResponses = channel.lifecycleQueryChaincodeDefinition(queryLifecycleQueryChaincodeDefinitionRequest, peers);
        //assertNotNull(queryChaincodeDefinitionProposalResponses);
        //assertEquals(peers.size(), queryChaincodeDefinitionProposalResponses.size());
        for (LifecycleQueryChaincodeDefinitionProposalResponse response : queryChaincodeDefinitionProposalResponses) {
            //assertEquals(ChaincodeResponse.Status.SUCCESS, response.getStatus());
            //assertEquals(expectedSequence, response.getSequence());
            if (expectedValidationParameter != null) {
                byte[] validationParameter = response.getValidationParameter();
                //assertNotNull(validationParameter);
                //assertArrayEquals(expectedValidationParameter, validationParameter);
            }
            if (null != expectedChaincodeCollectionConfiguration) {
                final ChaincodeCollectionConfiguration chaincodeCollectionConfiguration = response.getChaincodeCollectionConfiguration();
                //assertNotNull(chaincodeCollectionConfiguration);
                //assertArrayEquals(expectedChaincodeCollectionConfiguration.getAsBytes(), chaincodeCollectionConfiguration.getAsBytes());
            }
            ChaincodeCollectionConfiguration collections = response.getChaincodeCollectionConfiguration();
            //assertEquals(expectedInitRequired, response.getInitRequired());
            //assertEquals("escc", response.getEndorsementPlugin());
            //assertEquals("vscc", response.getValidationPlugin());
        }
    }
    public static long getSequence(String chaincodeName, HFClient client, Channel channel, Collection<Peer> peers){
        return 1;
    }
    public static void upgradeChaincode(TransactionRequest.Type type, String channelName, String chaincodeName, String version, Orderer orderer, Peer peer, String funcName, String[] args) throws Exception {
        //        Channel channel = getChannel(channelName);
        //        channel.addPeer(peer);
        //        channel.addOrderer(orderer);
        //        channel.initialize();
        //        UpgradeProposalRequest upgradeProposalRequest = fabricClient.getHfClient().newUpgradeProposalRequest();
        //        upgradeProposalRequest.setChaincodeLanguage(type);
        //        ChaincodeID chaincodeID = ChaincodeID.newBuilder().setName(chaincodeName).setVersion(version).build();
        //        upgradeProposalRequest.setChaincodeID(chaincodeID);
        //        upgradeProposalRequest.setFcn(funcName);
        //        upgradeProposalRequest.setArgs(args);
        //        ChaincodeEndorsementPolicy chaincodeEndorsementPolicy = new ChaincodeEndorsementPolicy();
        //        chaincodeEndorsementPolicy.fromYamlFile(ClasspathFileUtils.getFileFromSpringBootClassPath("endorsement_policy/my_endorsement_policy.yaml"));
        //        upgradeProposalRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);
        //        Collection<ProposalResponse> proposalResponses = channel.sendUpgradeProposal(upgradeProposalRequest);
        //        for (ProposalResponse proposalRespons : proposalResponses) {
        //            if (proposalRespons.getStatus().getStatus() != 200) {
        //                throw new Exception("ERROR");
        //            }
        //        }
        //        channel.sendTransaction(proposalResponses);
    }
    public static JSONObject invoke(HFClient client, Channel channel, String chaincodeName, String func, String... args) throws InvalidArgumentException, ProposalException, ProposalException, ExecutionException, InterruptedException {
        TransactionProposalRequest request = client.newTransactionProposalRequest();
        request.setChaincodeName(chaincodeName);
        request.setFcn(func);
        if(args!=null){
            request.setArgs(args);
        }
        request.setProposalWaitTime(30000);
        Collection<ProposalResponse> responses = channel.sendTransactionProposal(request);
        boolean successed=true;
        for (ProposalResponse pres : responses) {
            logger.info(GlobalUtils.getCurrentRequestPrefix()+"invoke>>>>"+chaincodeName+">>>>>"+func+": "+parseResponse(pres).toJSONString());
            if(pres.getStatus()!= ChaincodeResponse.Status.SUCCESS){
                successed=false;
            }
        }
        JSONObject rt=new JSONObject();
        if(successed){
            logger.info(GlobalUtils.getCurrentRequestPrefix()+"invoke endorse>>>>"+chaincodeName+">>>>>"+func+"......  ");
            CompletableFuture<BlockEvent.TransactionEvent> transactionEventCompletableFuture = channel.sendTransaction(responses);
            while (!transactionEventCompletableFuture.isDone()){
                Thread.sleep(100);
            }
            BlockEvent.TransactionEvent event = transactionEventCompletableFuture.get();
            ByteString payload = responses.iterator().next().getProposalResponse().getResponse().getPayload();
            if(payload!=null && payload.size()>0){
                String s = payload.toStringUtf8();
                logger.info(GlobalUtils.getCurrentRequestPrefix()+"invoke endorse>>>>"+chaincodeName+">>>>>"+func+"：  "+s);
                rt= (JSONObject)JSONObject.parse(s);
            }
            else{
                rt.put("ret",true);
            }
            rt.put("txid",event.getTransactionID());
        }
        else {
            JSONArray resp = FabricClient.parseResponse(responses);
            rt.put("ret",false);
            rt.put("responses",resp);
        }
        return rt;
    }
    public static JSONObject query(HFClient client, Channel channel, String chaincodeName, String func, String... args) throws InvalidArgumentException, ProposalException, ProposalException {
        QueryByChaincodeRequest request = QueryByChaincodeRequest.newInstance(new PeerAdmin(FabricConfig.FirstOrganization().getName()));
        request.setChaincodeName(chaincodeName);
        request.setFcn(func);
        if(args!=null){
            request.setArgs(args);
        }
        request.setProposalWaitTime(30000);
        Collection<ProposalResponse> responses = channel.queryByChaincode(request);
        JSONObject rt=new JSONObject();
        JSONArray ja=new JSONArray();
        boolean isVerified=true;
        for (ProposalResponse pres : responses) {
            logger.info(GlobalUtils.getCurrentRequestPrefix()+"query>>>>"+chaincodeName+">>>>>"+func+": "+parseResponse(pres).toJSONString());
            if(!pres.isVerified()){
                isVerified=false;
                JSONObject parse = new JSONObject();
                ProposalResponsePackage.Response response = pres.getProposalResponse().getResponse();
                parse.put("message",response.getMessage());
                parse.put("status",response.getStatus());
                if (parse != null) {
                    ja.add(parse);
                }
            }
            else {
                JSONObject parse = (JSONObject) JSONObject.parse(pres.getProposalResponse().getResponse().getPayload().toStringUtf8());
                if (parse != null) {
                    ja.add(parse);
                }
            }
        }
        if(isVerified && !ja.isEmpty()){
            rt = (JSONObject) ja.get(0);
        }
        else{
            rt.put("ret",isVerified);
            rt.put("result",ja);
        }
        return rt;
    }
    public static JSONObject  getTransaction(Channel channel,String txid) throws InvalidArgumentException, ProposalException, IOException {
        JSONObject ret=new JSONObject();
        TransactionInfo transactionInfo = channel.queryTransactionByID(txid);
        ret.put("transaction",getTransactionInfo(transactionInfo));
        BlockInfo blockInfo = channel.queryBlockByTransactionID(txid);
        ret.put("block",getBlockInfo(blockInfo));
        return  ret;
    }
}
