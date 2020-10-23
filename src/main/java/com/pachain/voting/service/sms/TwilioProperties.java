package com.pachain.voting.service.sms;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@ConfigurationProperties(prefix = "twilio.creds")
@Component
public class TwilioProperties {
    private  String accountSid;
    private  String authToken;
    private  String from;
}
