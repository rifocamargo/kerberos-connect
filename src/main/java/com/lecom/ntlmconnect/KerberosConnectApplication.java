package com.lecom.ntlmconnect;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class KerberosConnectApplication {

	public static void main(String[] args) {
		
		System.setProperty("java.security.krb5.realm", "lecom.local");
		System.setProperty("java.security.krb5.kdc", "lecom-ad-01.lecom.local");
		
		System.setProperty("sun.security.spnego.debug", "true");
    	System.setProperty("sun.security.krb5.debug", "true");
    	System.setProperty("javax.security.auth.useSubjectCredsOnly", "true");
    	System.setProperty("java.security.krb5.conf", "C:\\Users\\ricardo.camargo\\Documents\\NetBeansProjects\\kerberostest\\krb5.conf");
    	System.setProperty("java.security.auth.login.config", "C:\\Users\\ricardo.camargo\\Documents\\NetBeansProjects\\kerberostest\\login.conf");
		SpringApplication.run(KerberosConnectApplication.class, args);
	}
}
