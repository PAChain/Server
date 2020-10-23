package com.pachain.voting.service.entities.mappers;

import org.apache.ibatis.annotations.Mapper;

import javax.annotation.Resource;
import java.util.List;

@Mapper
@Resource
public interface VoteResultMapper {
    List<List<?>> queryVoteResult(String chainCode, String key, String state, String county, String precinctNumber, int seatID, String date, String start, String end, int offset, int limit);
    List<List<?>> getVoteResult(String chainCode, int electionID, String state, String county, String precinctNumber);
}
