package com.pachain.voting.service.fabric.config;

import lombok.Data;

@Data
public class CAConfig {
    private String name;
    private String url;
    private String certFile;
}
