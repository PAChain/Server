package com.pachain.voting.service.entities.modules;

import lombok.Data;

import java.util.Date;

@Data
public class VoteResultStatistics {
    private int votedCount;
    private int voteCount;
    public float percent;
    private Date latedVoteDate;
    private Date latedVotedDate;
}
