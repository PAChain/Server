package com.pachain.voting.service.fabric.config;

import lombok.Data;

@Data
public class OrderConfig {
    private  String name;
    private String url;
    private  String tlsCACertFile;
}
