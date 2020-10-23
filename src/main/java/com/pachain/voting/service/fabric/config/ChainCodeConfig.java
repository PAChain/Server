package com.pachain.voting.service.fabric.config;

import lombok.Data;

@Data
public class ChainCodeConfig {
    private String name;
    private  String voter;
    private  String ballot;
    private  String voted;
    private String endorsement;
}
