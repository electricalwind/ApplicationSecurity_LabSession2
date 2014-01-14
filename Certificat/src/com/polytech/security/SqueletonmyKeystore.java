package com.polytech.security;



import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.*;

import java.io.*;

public class SqueletonmyKeystore{

	static public void main(String argv[]){
		
		try{
		
		// create a keystore with "JKS"
        KeyStore ks = KeyStore.getInstance("JKS");

		// load the keystore from the one created with Keytool tool
            char[] password = "desstelecom".toCharArray();

            java.io.FileInputStream fis = null;
            try {
                fis = new java.io.FileInputStream("/Users/matthieujimenez/Documents/APP/ApplicationSecurity_LabSession2/Certificat/src/com/polytech/security/commandline/myKeyStore.jks");
                ks.load(fis, password);
            } finally {
                if (fis != null) {
                    fis.close();
                }
            }
		// checks if the key store contains your alias		
		boolean trouve=ks.containsAlias("matthieu");
		// get the certificate associated to your alias
		if (trouve){
            Certificate mat=ks.getCertificate("matthieu");
            // display it
            System.out.println(mat.toString());
            // retreive the public key of the certificate
            PublicKey pkmat=mat.getPublicKey();
            // retreive the alias private key from the keystore
            PrivateKey pk= (PrivateKey)ks.getKey("matthieu","matthieu".toCharArray());
            Signature signingEngine = Signature.getInstance("DSA");

            SignedObject so = new SignedObject("ma signature",pk,
                    signingEngine);
            Signature verificationEngine =
                    Signature.getInstance("DSA");
            if (so.verify(pkmat, verificationEngine))
                try {
                    Object myobj = so.getObject();
                    System.out.println(myobj);
                } catch (java.lang.ClassNotFoundException e) {};
        }



                 
		// getInstance of a signObject 
		// create a signedObject with 
			// an instance of test
			// the private key 
			// the signingEngine
 		
 		// verify the signature
		// display the result of the verification
		
		}catch(Exception e){System.out.println("error");}
		
		
	}
	
	static private class test implements Serializable{

	 // nothing
	}
}