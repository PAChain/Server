package com.pachain.voting.service.entities.services;

import com.pachain.voting.service.entities.mappers.VoteDetailMapper;
import com.pachain.voting.service.entities.modules.VoteDetail;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class VoteDetailService {
    @Autowired
    VoteDetailMapper voteDetailMapper;
    public List<VoteDetail> queryVoted(String chainCode,  QueryParams params){
        List<List<?>> list = voteDetailMapper.queryVoted(chainCode,params.getState(),params.getCounty(),params.getPrecinctNumber(),params.getBallotNumber(),params.getDate(),params.getStart(),params.getEnd(),params.getOffset(),params.getLimit());
        params.setCount(Integer.parseInt(list.get(1).get(0).toString()));
        return  (List<VoteDetail>)list.get(0);
    }
}
