package com.polytech.security;

import java.awt.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

/**
 * Class which give two static method, one to sign content the other to verify sign content
 */
public class KeyStoreEAP {
    /**
     * Methode to verify that a given sign was made by a given alias with a given text
     * @param path  Path to the JKS keystore
     * @param identity alias of the signer
     * @param sign Signature we want to verify
     * @param text original text
     * @return boolean wether the given sign was made by the given alias with the given text
     */
    static public boolean verifySign(String path,String identity,byte[] sign,byte[] text){
        java.io.FileInputStream fis = null;
        try{

            // create a keystore with "JKS"
            KeyStore ks = KeyStore.getInstance("JKS");

            // load the keystore from the one created with Keytool tool
            char[] password = "desstelecom".toCharArray();

            fis = null;
            try {
                fis = new java.io.FileInputStream(path);
                ks.load(fis, password);
            } finally {
                if (fis != null) {
                    fis.close();
                }
            }

            // checks if the key store contains your alias
            boolean trouve=ks.containsAlias(identity);

            // get the certificate associated to your alias
            if (trouve){

                //retrieve the certificat of the given alias
                Certificate sup=ks.getCertificate(identity);

                // retreive the public key of the certificate
                PublicKey pksup=sup.getPublicKey();

                //instance the signature verification engine
                Signature verificationEngine = Signature.getInstance("DSA");

                //initialize the verificationEngine with the public Key of the alias
                verificationEngine.initVerify(pksup);

                //give the original text to the verification engine
                verificationEngine.update(text);

                //verify the sign
                return verificationEngine.verify(sign);

            }

        }catch(Exception e){System.out.println("error");}

        //if there was a problem return false
        System.out.println("There was a problem with the alias");
        return false;
    }

    /**
     * Methode use to sign a given text, you need an already existant alias  and the password in the given JKS, in order to sign
     * @param path  path to the JKS
     * @param pass  password of the alias
     * @param identity  alias
     * @param text text to sign
     * @return the sign of the text
     */
    static public byte[] Sign(String path,String pass,String identity,byte[] text){
        java.io.FileInputStream fis = null;
        try{

            // create a keystore with "JKS"
            KeyStore ks = KeyStore.getInstance("JKS");

            // load the keystore from the one created with Keytool tool
            char[] password = "desstelecom".toCharArray();

            fis = null;
            try {
                fis = new java.io.FileInputStream(path);
                ks.load(fis, password);
            } finally {
                if (fis != null) {
                    fis.close();
                }
            }

            // checks if the key store contains your alias
            boolean trouve=ks.containsAlias(identity);

            // get the certificate associated to your alias
            if (trouve){
                Certificate sup=ks.getCertificate(identity);

                // retreive the private key of the certificate
                PrivateKey pk= (PrivateKey)ks.getKey(identity,pass.toCharArray());

                //instance the signature engine
                Signature signature = Signature.getInstance("DSA");

                //initialize the signature Engine with the private Key of the alias
                signature.initSign(pk);

                //give the text to sign to the signature engine
                signature.update(text);

                //return the signature
                return signature.sign();


            }
        }catch(Exception e){System.out.println("error");}

        return null;
    }
}
