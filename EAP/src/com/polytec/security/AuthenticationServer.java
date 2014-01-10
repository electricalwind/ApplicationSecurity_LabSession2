package com.polytec.security;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * The authenticator provides a authentication service. It handles requests from
 * the supplicant.
 */
public class AuthenticationServer {

	private static final int AUTHENTICATION_SERVER_PORT = 1080;


	/*
	 * Starts the authenticationServer: open a server socket and launch a thread that
	 * will handle the requests when a connexion is received.
	 */
	public static void main(String args[]) {
		ServerSocket ss;
		try {
			ss = new ServerSocket(AUTHENTICATION_SERVER_PORT);
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
				SupplicantHandler handler = new SupplicantHandler(s);
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

		private ObjectOutputStream toClient;
		private ObjectInputStream fromClient;

		private SupplicantHandler(Socket socket) throws IOException {
			fromClient = new ObjectInputStream(socket.getInputStream());
			toClient = new ObjectOutputStream(socket.getOutputStream());
		}

		/*
		 * loops indefinitely reading objects from the socket
		 * and forwarding them to the handleFrame method
		 */
		public void run() {
			while (true) { // Change this to implement clean shutdown
				try {
					Object o = fromClient.readObject();
					log("received object " + o);
					handleFrame((Frame) o);
				} catch (IOException iox) {
					//most probably the authenticationServer closed the socket
					log("supplicant disconnected");
					return;
				} catch (ClassNotFoundException cnfx) {
					cnfx.printStackTrace();
				}
			}
		}

		/*
		 * Sends a frame through the socket, to be read by the Supplicant
		 */
		private void sendFrame(Frame frame) {
			try {
				toClient.reset();
				toClient.writeObject(frame);
				toClient.flush();
			} catch (IOException iox) {
				iox.printStackTrace();
			}
		}

		/*
		 * handles a frame received from the supplicant.
		 */
		private void handleFrame(Frame frame) {
			//TODO implement the protocol logic.
			// If your code gets too long, feel free to create a "FrameHandler" class  
			// You can use the provided "sendFrame" method to send a frame to the client.
			
			// as an example, here we inc the frame's identifier,
			// and we send it back
			frame.identifier++;
			sendFrame(frame);
		}
	}

	static void log(String s) {
		System.out.println(s);
	}
}