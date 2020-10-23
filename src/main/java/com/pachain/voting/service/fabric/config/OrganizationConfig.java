package com.pachain.voting.service.fabric.config;

import lombok.Data;

import java.util.Map;

@Data
public class OrganizationConfig {
    private String name;
    private String MSPID;
    private String adminName;
    private String adminKeyFile;
    private String adminCertFile;
    private String userName;
    private String userKeyFile;
    private String userCertFile;
    private CAConfig ca;
    private Map<String,PeerConfig> peers;

    public PeerConfig getFirstPeer() {
        PeerConfig obj = null;
        for (Map.Entry<String, PeerConfig> entry : peers.entrySet()) {
            obj = entry.getValue();
            if (obj != null) {
                break;
            }
        }
        return  obj;
    }

}
