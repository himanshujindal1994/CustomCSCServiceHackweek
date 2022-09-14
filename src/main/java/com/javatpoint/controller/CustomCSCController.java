package com.javatpoint.controller;

import com.javatpoint.service.RSAWrappingRunner;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CustomCSCController {

    @RequestMapping("/seal")
    public String doSeal() throws Exception {
        RSAWrappingRunner.doSeal();
        return "Digital Seal applied!!";
    }
}
