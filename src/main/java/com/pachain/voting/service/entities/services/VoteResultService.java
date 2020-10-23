package com.pachain.voting.service.entities.services;

import com.pachain.voting.service.entities.mappers.VoteResultMapper;
import com.pachain.voting.service.entities.modules.VoteResult;
import com.pachain.voting.service.entities.modules.VoteResultStatistics;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class VoteResultService {
    @Autowired
    VoteResultMapper voteResultMapper;
    public List<VoteResult> queryVoteResult(String chainCode, QueryParams params){
        List<List<?>> list = voteResultMapper.queryVoteResult(chainCode, params.getKey(),params.getState(),params.getCounty(),params.getPrecinctNumber(),params.getSeatID(),params.getDate(),params.getStart(),params.getEnd(),params.getOffset(),params.getLimit());
        params.setCount(Integer.parseInt(list.get(1).get(0).toString()));
        return  (List<VoteResult>)list.get(0);
    }
    public List<VoteResult> getVoteResult(String chainCode, QueryParams params){
        List<List<?>> list = voteResultMapper.getVoteResult(chainCode, params.getElectionID(), params.getState(),params.getCounty(),params.getPrecinctNumber());
        params.setStatistics((List<VoteResultStatistics>) list.get(1));
        return  (List<VoteResult>)list.get(0);
    }
}
