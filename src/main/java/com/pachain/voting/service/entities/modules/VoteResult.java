package com.pachain.voting.service.entities.modules;

import lombok.Data;

import java.util.Date;

@Data
public class VoteResult {
    private String txid;
    private String votingNumber;
    private String verificationCode;
    private String key;
    private String state;
    private String county;
    private String precinctNumber;
    private int electionID;
    private int seatID;
    private int candidateID;
    private String candidateName;
    private Date votingDate;
    private int count;
    private float percent;

}
