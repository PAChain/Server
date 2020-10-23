package com.pachain.voting.service.sms;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@ConfigurationProperties(prefix = "nexmo.creds")
@Component
public class NexmoProperties {
    private String  apiKey;
    private  String secret;
    private String from;
}

