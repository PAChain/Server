package com.pachain.voting.service.entities.mappers;

import com.pachain.voting.service.entities.modules.Voter;
import org.apache.ibatis.annotations.Mapper;

import javax.annotation.Resource;
import java.util.Date;

@Mapper
@Resource
public interface VoterMapper {
    int register(Voter voter);
    Voter loadByVoterID(String voterID);
    Voter loadByEmail(String email);
    Voter loadByPublicKey(String publicKey);
    Voter loadByWalletPublicKey(String publicKey);
    Voter loadByAccessToken(String accessToken);
    int update(Voter voter);
    int updatePublicKey(int voterID,String keyType,String publicKey, String encryptKey);
    int updateAccessToken(int voterID,String accessToken);
    int updateWalletID(String voterID,String walletID, String publicKey, String privateKey,String mspID,String type,String version);
    int updatePhoto(int id,String photo);
    int updateImage(int voterID, String type, String image);
    int appendImage(int voterID, int id);
    int updateTempImage(String key, String type, String image);
    int approved(int id,String txid,int approved,Date approvedDate);
    int deleteByID(int id);
    int voted(String chainCode, String txid,String userKey, String ballotNumber, int electionID, Date votingDate);
    int checkVotingNumber(String votingNumber);
    int votedResult(String chainCode, String txid, String votingNumber,String verificationCode,String key, String state,String county,String precinctNumber,int electionID,int seatID,int candidateID,String candidateName, Date votingDate);
    int getPrecinctIDByNumber(String state,String county,String number);
}
