package com.pachain.voting.service.entities.services;

import com.pachain.voting.service.entities.mappers.VoterMapper;
import com.pachain.voting.service.entities.modules.Voter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class VoterService {
    @Autowired
    VoterMapper voterMapper;
    public int register(Voter voter){return voterMapper.register(voter);}
    public Voter loadByVoterID(String voterID){
        return voterMapper.loadByVoterID(voterID);
    }
    public Voter loadByEmail(String email){
        return voterMapper.loadByEmail(email);
    }
    public  Voter loadByPublicKey(String publicKey){
        return voterMapper.loadByPublicKey(publicKey);
    }
    public  Voter loadByWalletPublicKey(String publicKey){
        return voterMapper.loadByWalletPublicKey(publicKey);
    }
    public  Voter loadByAccessToken(String accessToken){
        return voterMapper.loadByAccessToken(accessToken);
    }
    public  int update(Voter voter){
        return voterMapper.update(voter);
    }
    public int updatePublicKey(Integer voterID,String keyType,String publicKey, String encryptKey){return voterMapper.updatePublicKey(voterID,keyType,publicKey,encryptKey);}
    public int updateAccessToken(Integer voterID,String accessToken){return voterMapper.updateAccessToken(voterID,accessToken);}
    public int updateWalletID(String voterID,String walletID, String publicKey, String privateKey,String mspID,String type,String version){
        return voterMapper.updateWalletID(voterID,walletID,publicKey,privateKey,mspID,type,version);
    }
    public  int updatePhoto(int id,String photo){
        return  voterMapper.updatePhoto(id,photo);
    }
    public  int updateImage(int voterID, String type, String image){
        return  voterMapper.updateImage(voterID,type,image);
    }
    public int appendImage(int voterID, int id){
        return  voterMapper.appendImage(voterID,id);
    }
    public  int updateTempImage(String key, String type, String image){
        return  voterMapper.updateTempImage(key,type,image);
    }
    public int approved(int id,String txid,int approved,Date approvedDate){
        return  voterMapper.approved(id,txid,approved,approvedDate);
    }
    public  int deleteByID(int id){
        return  voterMapper.deleteByID(id);
    }
    public  int voted(String chainCode, String txid,String userKey, String ballotNumber, int electionID, Date votingDate){
        return voterMapper.voted(chainCode,txid,userKey,ballotNumber,electionID, votingDate);
    }
    public int checkVotingNumber(String votingNumber){
        return  voterMapper.checkVotingNumber(votingNumber);
    }
    public int votedResult(String chainCode, String txid, String votingNumber,String verificationCode,String key, String state,String county,String precinctNumber,int electionID,int seatID,int candidateID, String candidateName,Date votingDate){
        return voterMapper.votedResult(chainCode, txid,votingNumber,verificationCode,key, state,county,precinctNumber,electionID,seatID,candidateID,candidateName,votingDate);
    }
    public int getPrecinctIDByNumber(String state,String county,String number){
        try {
            return voterMapper.getPrecinctIDByNumber(state, county, number);
        }catch (Exception ex){
            return 0;
        }
    }
}
