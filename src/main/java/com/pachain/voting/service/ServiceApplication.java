package com.pachain.voting.service;

import com.pachain.voting.service.common.GlobalUtils;
import com.pachain.voting.service.fabric.WalletClient;
import org.slf4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

@SpringBootApplication
@EnableConfigurationProperties
//@ComponentScan(basePackages = {"com.pachain.voting.service"})
public class ServiceApplication extends SpringBootServletInitializer {
    private static Logger logger = org.slf4j.LoggerFactory.getLogger(ServiceApplication.class);

    public static void main(String[] args) throws Exception {
        System.out.println("Token1: "+ WalletClient.GetToken("WALLET_NETWORK_admin"));
        System.out.println("Token2: "+ WalletClient.GetToken("admin"));
        displayPaths();
        ConfigurableApplicationContext run = SpringApplication.run(ServiceApplication.class, args);
        GlobalUtils.setApplicationContext(run);
    }

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
        displayPaths();
        return builder.sources(ServiceApplication.class);
    }
    public static void displayPaths() {
        try {
            DefaultResourceLoader resourceLoader = new DefaultResourceLoader();
            Resource resource = resourceLoader.getResource("");
            System.out.println("Resource Path: " + resource.getFile().getPath());
        }catch (Exception ex){
            System.out.println("Resource Path: " + ex.getMessage());
        }
        try {
            final Path path = Paths.get("path");
            System.out.println("Path: " + path.toUri().getPath());
        }catch (Exception ex){
            System.out.println("Path: " + ex.getMessage());
        }
        System.out.println("path="+new File("path").getPath());
        System.out.println("resource="+ServiceApplication.class.getResource("").getPath());
    }
}
