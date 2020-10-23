package com.pachain.voting.service.fabric;

import com.pachain.voting.service.common.ECCUtils;
import com.pachain.voting.service.common.GlobalUtils;
import com.pachain.voting.service.fabric.config.CAConfig;
import org.hyperledger.fabric.gateway.*;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric_ca.sdk.EnrollmentRequest;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.slf4j.Logger;

import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

public class WalletClient {
    private static Logger logger = org.slf4j.LoggerFactory.getLogger(WalletClient.class);
    public static Identity GetUserIdentity(String userName) throws Exception {
        Wallet wallet = Wallets.newFileSystemWallet(Paths.get("wallet"));
        return wallet.get(userName);
    }
    public static User GetUser(String userName) throws Exception {
        Wallet wallet = Wallets.newFileSystemWallet(Paths.get("wallet"));
        Identity identity = wallet.get(userName);
        if (identity != null) {
            X509Identity identityX509 = (X509Identity)identity;
            User user = new User() {
                @Override
                public String getName() {
                    return userName;
                }
                @Override
                public Set<String> getRoles() { return new HashSet<String>(); }
                @Override
                public String getAccount() {
                    return null;
                }
                @Override
                public String getAffiliation() {
                    return "";
                }
                @Override
                public Enrollment getEnrollment() {
                    return new Enrollment() {
                        @Override
                        public PrivateKey getKey() {
                            return identityX509.getPrivateKey();
                        }
                        @Override
                        public String getCert() {
                            return Identities.toPemString(identityX509.getCertificate());
                        }
                    };
                }
                @Override
                public String getMspId() {
                    return FabricConfig.FirstOrganization().getMSPID();
                }
            };
            return  user;
        }
        return null;
    }
    public static User getUser(String userName,X509Identity identity){
        User user = new User() {
            @Override
            public String getName() {
                return userName;
            }
            @Override
            public Set<String> getRoles() {
                return null;
            }
            @Override
            public String getAccount() {
                return null;
            }
            @Override
            public String getAffiliation() {
                return "";
            }
            @Override
            public Enrollment getEnrollment() {
                return new Enrollment() {
                    @Override
                    public PrivateKey getKey() {
                        return identity.getPrivateKey();
                    }
                    @Override
                    public String getCert() {
                        return Identities.toPemString(identity.getCertificate());
                    }
                };
            }
            @Override
            public String getMspId() {
                return FabricConfig.FirstOrganization().getMSPID();
            }
        };
        return user;
    }
    public  static  WalletResponse  NewUser(String userName) throws Exception {
        HFCAClient caClient = initializeCAClient();
        // Create a wallet for managing identities
        Wallet wallet = Wallets.newFileSystemWallet(Paths.get("wallet"));
        // Check to see if we've already enrolled the user.
        Identity identity = wallet.get(userName);
        if (identity != null) {
            return new WalletResponse(0,"An identity for the user \""+userName+"\" already exists in the wallet",null);
        }
        X509Identity adminIdentity = (X509Identity)wallet.get("admin");
        if (adminIdentity == null) {
            return new WalletResponse(0,"\"admin\" needs to be enrolled and added to the wallet first",null);
        }
        User admin = new User() {
            @Override
            public String getName() {
                return "admin";
            }
            @Override
            public Set<String> getRoles() {
                return null;
            }
            @Override
            public String getAccount() {
                return null;
            }
            @Override
            public String getAffiliation() {
                return "";
            }
            @Override
            public Enrollment getEnrollment() {
                return new Enrollment() {
                    @Override
                    public PrivateKey getKey() {
                        return adminIdentity.getPrivateKey();
                    }
                    @Override
                    public String getCert() {
                        return Identities.toPemString(adminIdentity.getCertificate());
                    }
                };
            }
            @Override
            public String getMspId() {
                return FabricConfig.FirstOrganization().getMSPID();
            }
        };
        // Register the user, enroll the user, and import the new identity into the wallet.
        RegistrationRequest registrationRequest = new RegistrationRequest(userName);
        //registrationRequest.setAffiliation("org1.orgs");
        registrationRequest.setEnrollmentID(userName);
        String enrollmentSecret = caClient.register(registrationRequest, admin);
        Enrollment enrollment = caClient.enroll(userName, enrollmentSecret);
        PrivateKey key = enrollment.getKey();
        X509Certificate certificate = ECCUtils.getX509CertificateFromString( enrollment.getCert());
        Identity user = Identities.newX509Identity(FabricConfig.FirstOrganization().getMSPID(),  certificate, key);
        wallet.put(userName, user);
        return new WalletResponse(1,"Successfully enrolled user \""+userName+"\" and imported it into the wallet",(X509Identity) user);
    }
    public  static  WalletResponse  RemoveUser(String userName) throws Exception {
        HFCAClient caClient = initializeCAClient();
        // Create a wallet for managing identities
        Wallet wallet = Wallets.newFileSystemWallet(Paths.get("wallet"));
        // Check to see if we've already enrolled the user.
        Identity identity = wallet.get(userName);
        if (identity == null) {
            return new WalletResponse(1,"Wallet not exists in the wallet",null);
        }
        X509Identity identityX509 = (X509Identity)identity;
        User user = new User() {
            @Override
            public String getName() {
                return userName;
            }
            @Override
            public Set<String> getRoles() {
                return null;
            }
            @Override
            public String getAccount() {
                return null;
            }
            @Override
            public String getAffiliation() {
                return "";
            }
            @Override
            public Enrollment getEnrollment() {
                return new Enrollment() {
                    @Override
                    public PrivateKey getKey() {
                        return identityX509.getPrivateKey();
                    }
                    @Override
                    public String getCert() {
                        return Identities.toPemString(identityX509.getCertificate());
                    }
                };
            }
            @Override
            public String getMspId() {
                return FabricConfig.FirstOrganization().getMSPID();
            }
        };
        caClient.revoke(user,userName,"revoke");
        wallet.remove(userName);
        return new WalletResponse(1,"Successfully revoke user \""+userName+"\" ",null);
    }
    public  static void EnrollAdmin()throws  Exception{
        HFCAClient caClient = initializeCAClient();
        // Create a wallet for managing identities
        Wallet wallet = Wallets.newFileSystemWallet(Paths.get("wallet"));
        // Check to see if we've already enrolled the admin user.
        if (wallet.get("admin") != null) {
            System.out.println("An identity for the admin user \"admin\" already exists in the wallet");
            return;
        }
        // Enroll the admin user, and import the new identity into the wallet.
        final EnrollmentRequest enrollmentRequestTLS = new EnrollmentRequest();
        //?????
        enrollmentRequestTLS.addHost("127.0.0.1");
        enrollmentRequestTLS.setProfile("tls");
        Enrollment enrollment = caClient.enroll("admin", "adminpw", enrollmentRequestTLS);
        Identity user = Identities.newX509Identity(FabricConfig.FirstOrganization().getMSPID(), enrollment);
        wallet.put("admin", user);
        System.out.println("Successfully enrolled user \"admin\" and imported it into the wallet");
    }
    public static  X509Identity GetIdentity(String token,String publicKey){
        try{
            X509Identity admin = (X509Identity) GetUserIdentity("WALLET_NETWORK_admin");
            if(admin==null){
                admin = (X509Identity) GetUserIdentity("admin");
            }
            Base64.Decoder decoder = Base64.getDecoder();
            Base64.Encoder encoder = Base64.getEncoder();
            byte[] decrypt = ECCUtils.decrypt(decoder.decode(token), (ECPrivateKey) admin.getPrivateKey());
            String userName = new String(decrypt, StandardCharsets.UTF_8);
            X509Identity user = (X509Identity) WalletClient.GetUserIdentity(userName);
            if(publicKey.equals(encoder.encodeToString(user.getCertificate().getPublicKey().getEncoded()))){
                return  user;
            }
        }
        catch (Exception ex){
            System.console().printf(ex.getMessage());
        }
        return  null;
    }
    public  static String GetToken(String userName){
        try{
            if(userName==null || userName.isEmpty()||userName.length()==0){
                userName="admin";
            }
            X509Identity admin = (X509Identity)WalletClient.GetUserIdentity(userName);
            Base64.Encoder encoder = Base64.getEncoder();
            String tokenString="WALLET_RAW_TOKEN";
            return encoder.encodeToString(ECCUtils.encrypt(tokenString.getBytes(StandardCharsets.UTF_8),(ECPublicKey) admin.getCertificate().getPublicKey())) ;
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        return  "";
    }
    public  static  boolean CheckToken(String token){
        try{
            Base64.Decoder decoder = Base64.getDecoder();
            String tokenString="WALLET_RAW_TOKEN";
            X509Identity admin = (X509Identity) GetUserIdentity("WALLET_NETWORK_admin");
            if(admin!=null){
                try {
                    String ds = new String(ECCUtils.decrypt(decoder.decode(token), (ECPrivateKey) admin.getPrivateKey()), StandardCharsets.UTF_8);
                    if (ds.equals(tokenString)) {
                        return true;
                    }
                }catch (Exception e){}
            }
            admin = (X509Identity) GetUserIdentity("admin");
            if(admin!=null){
                try {
                    String ds = new String(ECCUtils.decrypt(decoder.decode(token), (ECPrivateKey) admin.getPrivateKey()), StandardCharsets.UTF_8);
                    if (ds.equals(tokenString)) {
                        return true;
                    }
                }catch (Exception e){}
            }
            return  false;
        }
        catch (Exception ex){
            logger.error(GlobalUtils.getException(ex));
        }
        return  false;
    }
    private static HFCAClient initializeCAClient() throws InvalidArgumentException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException, org.hyperledger.fabric.sdk.exception.CryptoException, MalformedURLException {
        Properties props = new Properties();
        CAConfig ca = FabricConfig.FirstOrganization().getCa();
        props.put("pemFile",ca.getCertFile());
        props.put("allowAllHostNames", "true");
        HFCAClient client = HFCAClient.createNewInstance(ca.getUrl(),props);
        client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        return client;
    }
}
