package com.polytech.security;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Supplicant {

	private static final String DEFAULT_AUTHENTICATION_SERVER_HOST = "localhost";
	private static final String DEFAULT_MAN_IN_THE_MIDDLE_HOST = "localhost";
	private static final int DEFAULT_authenticationServer_PORT = 1080;
	private static final int DEFAULT_MAN_IN_THE_MIDDLE_PORT = 1079;
	
	private ObjectInputStream fromServer;
	private ObjectOutputStream toServer;

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
	public void authenticate() {
		// TODO: implement the supplicant-side of the protocol here
		
		// Get server identity request
		Frame authenticationServerIDRequest = readFrame();
		
		if (authenticationServerIDRequest.code != Frame.CODE_REQUEST || authenticationServerIDRequest.data.type != Data.TYPE_IDENTITY)
		{
			System.err.println("Bad message");
			System.exit(-1);
		}
		
		System.out.println("Get authentication server id= " + authenticationServerIDRequest.data);
			
		
		// Send my identity
		Data dataIdentity = new Data(Data.TYPE_IDENTITY, "SUPPLICANT_ID".getBytes());
		Frame dataFrame = new Frame(Frame.CODE_RESPONSE, (new Integer(2)).byteValue(), dataIdentity);
		
		sendFrame(dataFrame);
		
		// Get MD5 message request
		Frame md5ChallengeRequest = readFrame();
		
		if (md5ChallengeRequest.code != Frame.CODE_REQUEST || md5ChallengeRequest.data.type != Data.TYPE_MD5_CHALLENGE)
		{
			System.err.println("Bad message");
			System.exit(-1);
		}
		
		Data md5challengeData = md5ChallengeRequest.data;
		System.out.println("The challenge sent by Server : " + Arrays.toString(md5challengeData.data));
		
		// Compute Challenge MD5 and send it to AuthenticationServer
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] md5challenge = md.digest(md5challengeData.data);
			Data md5ChallengeRespondData = new Data(Data.TYPE_MD5_CHALLENGE, md5challenge);
			Frame md5ChallengeRespondFrame = new Frame(Frame.CODE_RESPONSE, md5ChallengeRequest.identifier++, md5ChallengeRespondData);
			System.out.println("Coucou");
			sendFrame(md5ChallengeRespondFrame);
			
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error with MD5 algorithm");
		}
		
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
		supplicant.connect(DEFAULT_AUTHENTICATION_SERVER_HOST , 
						   DEFAULT_authenticationServer_PORT);
		supplicant.authenticate();
	}
}