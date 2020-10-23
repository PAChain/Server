package com.pachain.voting.service.fabric.config;

import lombok.Data;

@Data
public class PeerConfig {
    private String name;
    private String url;
    private String tlsCACertFile;
    private String tlsClientKeyFile;
    private String tlsClientCertFile;
}
