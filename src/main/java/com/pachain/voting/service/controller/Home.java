package com.pachain.voting.service.controller;

import com.pachain.voting.service.common.ECCUtils;
import com.pachain.voting.service.common.GlobalUtils;
import com.pachain.voting.service.entities.services.VoterService;
import com.pachain.voting.service.sms.Nexmo;
import com.pachain.voting.service.sms.Twilio;
import com.pachain.voting.service.fabric.WalletClient;
import org.hyperledger.fabric.gateway.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

@Controller
public class Home {
    @Autowired
    private VoterService voterService;
    @Autowired
    private Nexmo nexmo;
    @Autowired
    private Twilio twilio;
    @RequestMapping("/")
    @ResponseBody
    public  String Index(){
        try {
            final String s = GlobalUtils.GetRSAPublicKey();
            final String s1 = GlobalUtils.GetECCPublicKey();
            System.out.println("RSA: "+s.length()+"; ECC: "+s1.length());
        }
        catch (Exception ex){
            System.out.println(ex.getMessage());
        }
        return  "Index";
    }
    private void  GeneralKeys() throws Exception {
        Base64.Encoder encoder = Base64.getEncoder();
        X509Identity admin = (X509Identity)WalletClient.GetUserIdentity("admin");
        for(Integer x=1;x<=10;x++){
            String userName="WALLET_NETWORK_" + x.toString();
            try {
                String token = encoder.encodeToString(ECCUtils.encrypt(userName.getBytes(StandardCharsets.UTF_8), (ECPublicKey) admin.getCertificate().getPublicKey()));
                FileWriter fw = new FileWriter("d:\\Test\\" + x.toString() + "_token.txt");
                fw.write(token);
                fw.close();
            }catch (Exception ex){}
            //WalletResponse walletResponse = WalletClient.NewUser("WALLET_NETWORK_" + x.toString());
            //X509Identity identity =walletResponse.getIdentity();
            X509Identity identity =(X509Identity)WalletClient.GetUserIdentity("WALLET_NETWORK_" + x.toString());
            try
            {
                String encoded=encoder.encodeToString(identity.getPrivateKey().getEncoded());
                FileWriter fw=new FileWriter("d:\\Test\\"+x.toString()+"_private.pem");
                fw.write("-----BEGIN PRIVATE KEY-----\n");
                fw.write(encoded);
                fw.write("\n");
                fw.write("-----END PRIVATE KEY-----");
                fw.close();
            } catch (Exception ex)
            {
                ex.printStackTrace();
            }
            try
            {
                String encoded=encoder.encodeToString(identity.getCertificate().getPublicKey().getEncoded());
                FileWriter fw=new FileWriter("d:\\Test\\"+x.toString()+"_public.pem");
                fw.write("-----BEGIN PUBLIC KEY-----\n");
                fw.write(encoded);
                fw.write("\n");
                fw.write("-----END PUBLIC KEY-----");
                fw.close();
            } catch (Exception ex)
            {
                ex.printStackTrace();
            }
            try{
                String encoded=encoder.encodeToString(identity.getCertificate().getEncoded());
                FileWriter fw=new FileWriter("d:\\Test\\"+x.toString()+".crt");
                fw.write("-----BEGIN CERTIFICATE-----\n");
                fw.write(encoded);
                fw.write("\n");
                fw.write("-----BEGIN CERTIFICATE-----");
                fw.close();
            } catch (Exception ex){
                ex.printStackTrace();
            }
        }
    }
    private static String getFileContent(String path){
        try{
            FileReader reader = new FileReader(path);
            BufferedReader br = new BufferedReader(reader);
            String line;
            StringBuilder result = new StringBuilder();
            while ((line = br.readLine()) != null) {
                result.append(line+"\n");
            }
            String ret = result.toString();
            br.close();;
            reader.close();;
            return  ret;
        }catch (Exception ex){}
        return "";
    }

    @RequestMapping("/voteinvite")
    public  String VoteInvite(Model model){
        model.addAttribute("pm","VoteInvite");
        return  "VoteInvite";
    }
}
