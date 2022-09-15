package com.javatpoint.controller;

import com.javatpoint.service.RSAWrappingRunner;
import com.javatpoint.utils.LoginHSM;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.Security;

@RestController
public class CustomCSCController {

    static{

        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
            BouncyCastleProvider provider = new BouncyCastleProvider();
            Security.addProvider(provider);
            LoginHSM.login();
        } catch (Exception e) {
            e.printStackTrace();
        }


    }

    @RequestMapping("/register")
    public String doRegister(@RequestParam(name = "keyAlias") String label) throws Exception {
        RSAWrappingRunner.doRegister(label);
        return "Registration Completed!!";
    }

    @RequestMapping("/sign")
    public String doSign(@RequestParam(name = "inDoc") String src, @RequestParam(name = "outDoc") String dest, @RequestParam(name = "keyHandle") String handle) throws Exception {
        RSAWrappingRunner.doSign(src, dest);
        return "Digital Signature applied!!";
    }

    @RequestMapping("/signature")
    public String doSignature(@RequestParam(name = "inDoc") String src, @RequestParam(name = "outDoc") String dest, @RequestParam(name = "keyAlias") String label) throws Exception {
        RSAWrappingRunner.doSignature(src, dest, label);
        return "Digital Signature applied!!";
    }

    @RequestMapping("/signDoc")
    public ResponseEntity<?> doSignDoc(@RequestParam(name = "inDoc") String src, @RequestParam(name = "outDoc") String dest, @RequestParam(name = "keyAlias") String label) throws Exception {
        return RSAWrappingRunner.doSignDoc(src, dest, label);
    }

}
