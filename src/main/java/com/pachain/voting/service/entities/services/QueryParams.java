package com.pachain.voting.service.entities.services;

import com.pachain.voting.service.entities.modules.VoteResultStatistics;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
public class QueryParams {
    private  String key;
    private String state;
    private String county;
    private String precinctNumber;
    private String ballotNumber;
    private int electionID;
    private int seatID;
    private String date;
    private String start;
    private String end;
    private int offset;
    private int limit;
    private int count;

    private List<VoteResultStatistics> statistics;
}
