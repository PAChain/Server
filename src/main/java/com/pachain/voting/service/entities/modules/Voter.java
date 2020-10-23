package com.pachain.voting.service.entities.modules;

import lombok.Data;

import java.sql.Timestamp;
import java.util.Date;

@Data
public class Voter {
    private Integer id;
    private  String voterID;
    private String precinctID;
    private String precinctNumber;
    private  String email;
    private String firstName;
    private String middleName;
    private String lastName;
    private String nameSuffix;
    private  String cellphone;
    private String state;
    private String county;
    private String city;
    private String address;
    private  String photo;
    private String certificateType;
    private String certificate;
    private  String walletID;
    private  String walletPublicKey;
    private  String walletPrivateKey;
    private  String walletMSPID;
    private  String walletType;
    private  String walletVersion;
    private  String keyType;
    private  String publicKey;
    private String encryptKey;
    private String accessToken;
    private Date registerDate;
    private Timestamp lastModify;
    private String txid;
    private int approved;
    private Date approvedDate;
}
