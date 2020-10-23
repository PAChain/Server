package com.pachain.voting.service.sms;

import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class Twilio {
    @Autowired
    private TwilioProperties twilioProperties;
    private static Logger logger = org.slf4j.LoggerFactory.getLogger(Twilio.class);
    public  boolean IsReady(){
        return  twilioProperties.getAccountSid().length()>0 && twilioProperties.getAuthToken().length()>0;
    }
    public  boolean  SendMessage(String to, String msg){
        com.twilio.Twilio.init(twilioProperties.getAccountSid(),twilioProperties.getAuthToken());
        Message message = Message.creator(
                new PhoneNumber(to),  // To number ,Phone number with area code
                new PhoneNumber(twilioProperties.getFrom()),  // From number
                msg // SMS body
        ).create();
        if (! StringUtils.isEmpty(message.getSid())){
            System.out.println(message.getSid());
        }
        return message.getStatus()!= Message.Status.FAILED;
    }
}
