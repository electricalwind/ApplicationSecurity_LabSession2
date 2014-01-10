package com.polytech.security;


import java.security.*;
import java.security.cert.*;
import java.security.interfaces.*;

import java.io.*;

public class SqueletonmyKeystore{

	static public void main(String argv[]){
		
		try{
		
		// create a keystore with "JKS"
		// load the keystore from the one created with Keytool tool

		// checks if the key store contains your alias		
		
		// get the certificate associated to your alias
		
		// display it

		// retreive the public key of the certificate
		
		// retreive the alias private key from the keystore
                 
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