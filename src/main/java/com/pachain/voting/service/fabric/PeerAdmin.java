package com.pachain.voting.service.fabric;

import com.pachain.voting.service.common.GlobalUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.slf4j.Logger;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

public class PeerAdmin implements User {
    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    private static Logger logger = org.slf4j.LoggerFactory.getLogger(PeerAdmin.class);
    private String Org="";
    public  PeerAdmin(String org){
        super();
        this.Org=org;
    }
    @Override
    public String getName() {
        return FabricConfig.Organizations.get(this.Org).getName();
    }
    @Override
    public Set<String> getRoles() {
        return new HashSet<String>();
    }
    @Override
    public String getAccount() {
        return "";
    }
    @Override
    public String getAffiliation() {
        return "";
    }
    @Override
    public String getMspId() {
        return FabricConfig.Organizations.get(this.Org).getMSPID();
    }
    @Override
    public Enrollment getEnrollment() {
        return new Enrollment() {
            @Override
            public PrivateKey getKey() {
                try {
                    return getPrivateKeyFromBytes(IOUtils.toByteArray(new FileInputStream(FabricConfig.Organizations.get(Org).getAdminKeyFile())));
                } catch (IOException e) {
                    logger.error(GlobalUtils.getException(e));
                    return null;
                }
            }
            @Override
            public String getCert() {
                try {
                    return new String(Files.readAllBytes(Paths.get(FabricConfig.Organizations.get(Org).getAdminCertFile())));
                } catch (IOException e) {
                    logger.error(GlobalUtils.getException(e));
                    return "";
                }
            }
        };
    }
    public  X509Certificate getX509Cert(){
        try {
            return getCertificate(Files.readAllBytes(Paths.get(FabricConfig.Organizations.get(this.Org).getAdminCertFile())));
        } catch (IOException | CertificateException e) {
            logger.error(GlobalUtils.getException(e));
            return null;
        }
    }
    public static PrivateKey getPrivateKeyFromBytes(byte[] data) throws IOException {
        final Reader pemReader = new StringReader(new String(data));
        final PrivateKeyInfo pemPair;
        try (PEMParser pemParser = new PEMParser(pemReader)) {
            pemPair = (PrivateKeyInfo) pemParser.readObject();
        }
        return new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getPrivateKey(pemPair);
    }
    public  static X509Certificate getCertificate(byte[] data) throws CertificateException {
        PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(data)));
        X509Certificate certificate;
        try {
            Object object = pemParser.readObject();
            if (object instanceof X509CertificateHolder) {
                certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate((X509CertificateHolder) object);
            } else {
                throw new CertificateException("Unsupported certificate type, not an X509CertificateHolder.");
            }
        } catch (IOException ex) {
            logger.error(GlobalUtils.getException(ex));
            throw new CertificateException("Failed to read certificate.", ex);
        } finally {
            try {
                pemParser.close();
            } catch (IOException e) {
                logger.error(GlobalUtils.getException(e));
                throw new CertificateException("Failed to close certificate reader.", e);
            }
        }
        if (certificate == null) {
            throw new CertificateException("Failed to read certificate. The security provider could not parse it.");
        }
        return certificate;
    }
}
