package com.pachain.voting.service.entities.modules;

import lombok.Data;

import java.util.Date;

@Data
public class VoteDetail
{
    private String state;
    private String county;
    private String precinctNumber;
    private Date votingDate;
    private int count;
}
