package com.pachain.voting.service.sms;

import com.nexmo.client.NexmoClient;
import com.nexmo.client.NexmoClientException;
import com.nexmo.client.sms.SmsClient;
import com.nexmo.client.sms.SmsSubmissionResponse;
import com.nexmo.client.sms.SmsSubmissionResponseMessage;
import com.nexmo.client.sms.messages.TextMessage;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;


import java.io.IOException;

@Component
public class Nexmo {
    @Autowired
    private NexmoProperties nexmoProperties;
    private static Logger logger = org.slf4j.LoggerFactory.getLogger(Nexmo.class);
    public  boolean IsReady(){
        return  nexmoProperties.getApiKey().length()>0 && nexmoProperties.getSecret().length()>0;
    }
    //@Bean
    public NexmoClient customNexmoBuilder() {
        return NexmoClient.builder()
                .apiKey(nexmoProperties.getApiKey())
                .apiSecret(nexmoProperties.getSecret())
                //.httpConfig(HttpConfig.builder().baseUri("https://example.com").build())
                .build();
    }
    public  boolean  SendMessage(String to, String message) throws IOException, NexmoClientException {
        NexmoClient builder = customNexmoBuilder();
        SmsClient smsClient = builder.getSmsClient();
        try {
            SmsSubmissionResponse smsSubmissionResponse = smsClient.submitMessage(new TextMessage(
                    nexmoProperties.getFrom(),
                    to,
                    message));
            boolean successed=false;
            if(smsSubmissionResponse.getMessageCount()>0){
                for (SmsSubmissionResponseMessage response : smsSubmissionResponse.getMessages()) {
                    if(response.getStatus().getMessageStatus()==0){successed=true;}
                    System.out.println(response.getId()+", "+response.getStatus()+", "+response.getErrorText());
                }
            }
            return successed;
        } catch (IOException e) {
            logger.error(e.getMessage()+"\n"+e.getStackTrace());
        } catch (NexmoClientException e) {
            logger.error(e.getMessage()+"\n"+e.getStackTrace());
        }
        return  false;
    }
}
