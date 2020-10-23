package com.pachain.voting.service.entities.mappers;


import org.apache.ibatis.annotations.Mapper;

import javax.annotation.Resource;
import java.util.List;

@Mapper
@Resource
public interface VoteDetailMapper {
    List<List<?>> queryVoted(String chainCode, String state, String county, String precinctNumber,String ballotnumber, String date, String start, String end, int offset,int limit);
}
