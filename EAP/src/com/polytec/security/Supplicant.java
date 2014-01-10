package com.polytec.security;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;

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
		
		// as an example, we connect, send an empty frame and print the response
		sendFame(new Frame());
		System.out.println(readFrame());
	}

	private void sendFame(Frame frame) {
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