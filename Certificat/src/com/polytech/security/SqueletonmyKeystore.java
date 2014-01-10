package com.polytech.security;


import com.sun.org.apache.xalan.internal.xsltc.compiler.util.TestGenerator;

import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.*;

import java.io.*;

public class SqueletonmyKeystore{

	static public void main(String argv[]){
        if(argv.length==3){
		try{
		
		// create a keystore with "JKS"
        KeyStore ks = KeyStore.getInstance("JKS");

		// load the keystore from the one created with Keytool tool
            char[] password = "desstelecom".toCharArray();

            java.io.FileInputStream fis = null;
            try {
                fis = new java.io.FileInputStream(argv[0]);
                ks.load(fis, password);
            } finally {
                if (fis != null) {
                    fis.close();
                }
            }
		// checks if the key store contains your alias		
		boolean trouve=ks.containsAlias(argv[1]);
		// get the certificate associated to your alias
		if (trouve){
            Certificate mat=ks.getCertificate(argv[1]);
            // display it
            System.out.println(mat.toString());
            // retreive the public key of the certificate
            PublicKey pkmat=mat.getPublicKey();
            // retreive the alias private key from the keystore
            PrivateKey pk= (PrivateKey)ks.getKey(argv[1],argv[2].toCharArray());
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
		
		}catch(Exception e){System.out.println("error");}
		
		
	}

    else{
        System.out.println("java SqueletonmyKeyStore pathToJKS alias password");
    }
    }
	static private class test implements Serializable{

	 // nothing
	}
}