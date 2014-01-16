package com.polytech.security;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignedObject;
import java.util.Arrays;


public class Supplicant {

	private static final String DEFAULT_AUTHENTICATION_SERVER_HOST = "localhost";
	private static final String DEFAULT_MAN_IN_THE_MIDDLE_HOST = "localhost";
	private static final int DEFAULT_authenticationServer_PORT = 1080;
	private static final int DEFAULT_MAN_IN_THE_MIDDLE_PORT = 1079;

	private ObjectInputStream fromServer;
	private ObjectOutputStream toServer;
    private String path;

	public void connect(String authenticationServerHost, int authenticationServerPort) {
		try {
			Socket socket = new Socket(authenticationServerHost, authenticationServerPort);
			toServer = new ObjectOutputStream(socket.getOutputStream());
			fromServer = new ObjectInputStream(socket.getInputStream());
		} catch (UnknownHostException uhx) {
			uhx.printStackTrace();
		} catch (IOException iox) {
			iox.printStackTrace();
		}
	}

	/*
	 * connects to an authenticationServer and authenticates to it.
	 */
	public void authenticate(String argv) {
		// Get server identity request
		Frame authenticationServerIDRequest = readFrame();
        System.out.println("Connection Successful");
		if (authenticationServerIDRequest.code != Frame.CODE_REQUEST || authenticationServerIDRequest.data.type != Data.TYPE_IDENTITY)
		{
			System.err.println("Bad message");
			System.exit(-1);
		}
		System.out.println("Get authentication server id= " + authenticationServerIDRequest.data);


		// Send my identity
		Data dataIdentity = new Data(Data.TYPE_IDENTITY, "supplicant".getBytes());
		Frame dataFrame = new Frame(Frame.CODE_RESPONSE, (new Integer(2)).byteValue(), dataIdentity);

		sendFrame(dataFrame);

		// Get MD5  or TLS message request
		Frame md5orTLSChallengeRequest = readFrame();

        //verify it
		if (md5orTLSChallengeRequest.code != Frame.CODE_REQUEST || (md5orTLSChallengeRequest.data.type != Data.TYPE_MD5_CHALLENGE && md5orTLSChallengeRequest.data.type != Data.TYPE_TLS_CHALLENGE))
		{
			System.err.println("Bad message");
			System.exit(-1);
		}
        //if TLS
        if (md5orTLSChallengeRequest.data.type == Data.TYPE_TLS_CHALLENGE){
            System.out.println("The TLS challenge sent by Server : " + Arrays.toString(md5orTLSChallengeRequest.data.data));
            //Sign the Challenge
            byte[] so= KeyStoreEAP.Sign(argv,"supplicant","supplicant",md5orTLSChallengeRequest.data.data);

            //generate the Data part of the frame
            Data tlsData = new Data(Data.TYPE_TLS_CHALLENGE,so);

            //generate the Frame
            Frame tlsFrame=new Frame(Frame.CODE_RESPONSE,++md5orTLSChallengeRequest.identifier,tlsData);

            //send Frame
            sendFrame(tlsFrame);
        }
        //If MD5
        else{

		System.out.println("The MD5 challenge sent by Server : " + Arrays.toString(md5orTLSChallengeRequest.data.data));

		// Compute Challenge MD5 and send it to AuthenticationServer
		try {
            //digest Challenge
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] md5challenge = md.digest(md5orTLSChallengeRequest.data.data);

            //generate the Data part of the frame
			Data md5ChallengeRespondData = new Data(Data.TYPE_MD5_CHALLENGE, md5challenge);

            //generate the Frame
			Frame md5ChallengeRespondFrame = new Frame(Frame.CODE_RESPONSE, md5orTLSChallengeRequest.identifier++, md5ChallengeRespondData);

            //send Frame
            sendFrame(md5ChallengeRespondFrame);

		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error with MD5 algorithm");
		}
        }
		// Get EAP response
		Frame eapResponse = readFrame();

        //prepare Result message
		String response = "Server reponse: " + new String(eapResponse.data.data);
		
		if (eapResponse.code == Frame.CODE_SUCCESS)
			System.out.println(response);
		else
			System.err.println(response);

	}

	private void sendFrame(Frame frame) {
		try {
			toServer.writeObject(frame);
		} catch (IOException iox){
			iox.printStackTrace();
		}
	}

	/*
	 * blocks until a frame is read from the authenticationServer, then return that frame
	 */
	private Frame readFrame() {
		try {
			return (Frame) fromServer.readObject();
		} catch (IOException iox) {
			iox.printStackTrace();
		} catch (ClassNotFoundException cnfx) {
			cnfx.printStackTrace();
		}
		return null;
	}

	public static void main(String argv[]) {
		Supplicant supplicant = new Supplicant();
		int value=0;
		if (argv.length!=2){
            System.out.println("You didn't give the right number of parameter to the program");
            System.out.println("First you must indicate the path to your JKS session");
            System.out.println("Then you enter the mode you want to test");
            System.out.println("Either 0 for Normal or 1 for Man In The Middle");
			System.exit(0);
        }
		else
            value=Integer.valueOf(argv[1]);

		switch (value){
		case 1: System.out.println("Trying to reach Man In The Middle ...");
                supplicant.connect(DEFAULT_MAN_IN_THE_MIDDLE_HOST ,
				DEFAULT_MAN_IN_THE_MIDDLE_PORT);
		break;
		default:System.out.println("Trying to reach AuthenticationServer ...");
                supplicant.connect(DEFAULT_AUTHENTICATION_SERVER_HOST ,
				DEFAULT_authenticationServer_PORT);
		break;
		}
		supplicant.authenticate(argv[0]);

	}
}