package com.pachain.voting.service.fabric;

import lombok.Getter;
import lombok.Setter;
import org.hyperledger.fabric.gateway.X509Identity;

@Setter
@Getter
public class WalletResponse {
    private X509Identity identity;
    private Integer status;
    private String message;
    public  WalletResponse(Integer status, String message,X509Identity identity){
        this.setStatus(status);
        this.setMessage(message);
        this.setIdentity(identity);
    }
}
