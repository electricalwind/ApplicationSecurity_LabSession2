package com.polytech.security;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.UUID;

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
	public static void main(String argv[]) {
		ServerSocket ss;
        int mode=0;
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
                if (argv.length!=2){
                    System.out.println("You didn't give the right number of parameter to the program (2)");
                    System.out.println("First you must indicate the path to your JKS session");
                    System.out.println("Then you enter the mode of Authentification you want to test");
                    System.out.println("Either 0 for MD5 or 1 for TLS");
                    System.exit(0);
                }else {

                mode=Integer.parseInt(argv[1]);
                    if(mode==1)
                        System.out.println("You choose TLS Authentification");
                    else
                        System.out.println("You choose MD5 Authentification");
                }



				SupplicantHandler handler = new SupplicantHandler(s,mode,argv[0]);
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
		private String challenge;
        private int mode;
        private String path;
        private String identity;

		private SupplicantHandler(Socket socket,int mode,String path) throws IOException {
			fromClient = new ObjectInputStream(socket.getInputStream());
			toClient = new ObjectOutputStream(socket.getOutputStream());
            this.mode=mode;
            this.path=path;
		}

		/*
		 * loops indefinitely reading objects from the socket
		 * and forwarding them to the handleFrame method
		 */
		public void run() {

			Data data = new Data(Data.TYPE_IDENTITY, "serveur".getBytes());
			Frame frame = new Frame(Frame.CODE_REQUEST, (new Integer(1)).byteValue(), data);
			sendFrame(frame);


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
            Data dataChallenge;

            //if the server receive a response to his identity request
			if (frame.code == Frame.CODE_RESPONSE && frame.data.type == Data.TYPE_IDENTITY)
			{	

				System.out.println("Supplicant identified");

                //save the identity
                this.identity=new String(frame.data.data);

				// Generate challenge to supplicant
				this.challenge = UUID.randomUUID().toString();

                //if EAP-MD5 Authentification
                if (mode==0)
				dataChallenge = new Data(Data.TYPE_MD5_CHALLENGE, challenge.getBytes());
                else
                //if EAP_TLS Authentification
                dataChallenge = new Data(Data.TYPE_TLS_CHALLENGE, challenge.getBytes());

                //Send Frame
				Frame frameChallenge = new Frame(Frame.CODE_REQUEST, ++frame.identifier, dataChallenge);

				System.out.println("Challenge sent to supplicant : " + Arrays.toString(this.challenge.getBytes()));
				sendFrame(frameChallenge);
			}
			
			// Get response to challenge
			if (frame.code == Frame.CODE_RESPONSE && (frame.data.type == Data.TYPE_MD5_CHALLENGE ||frame.data.type == Data.TYPE_TLS_CHALLENGE))
			{

                boolean ok=false;
				try {

                    //if response to a MD5-Challenge
                    if (frame.data.type==Data.TYPE_MD5_CHALLENGE) {
                        MessageDigest md = MessageDigest.getInstance("MD5");
                        byte[] localChallengeDigest = md.digest(this.challenge.getBytes());
                        // Compare local and remote MD5 hash
                        ok= Arrays.equals(localChallengeDigest, frame.data.data);
                    }
                    //if response to a TLS-Challenge
                    else
                     //verify sign
                     ok=KeyStoreEAP.verifySign(this.path,this.identity,frame.data.data,this.challenge.getBytes());

                    //if AUthentification Success
					if (ok){
						System.out.println("Client authentified with EAP protocol!");
						
						Data dataEAPSuccess = new Data(Data.TYPE_NOTIFICATION, new String("EAP_SUCCESS").getBytes());
						Frame frameEAPSuccess = new Frame(Frame.CODE_SUCCESS, ++frame.identifier, dataEAPSuccess);
						sendFrame(frameEAPSuccess);
					}
                    //if error
					else {
						System.err.println("Error with MD5 challenge");
						
						Data dataEAPFailure = new Data(Data.TYPE_NOTIFICATION, new String("EAP_FAILURE").getBytes());
						Frame frameEAPFailure = new Frame(Frame.CODE_FAILURE, ++frame.identifier, dataEAPFailure);
						sendFrame(frameEAPFailure);
					}
				} catch (NoSuchAlgorithmException e) {
					System.err.println("Error with MD5 algorithm");
				}
				
				

			}

		}
	}



	static void log(String s) {
		System.out.println(s);
	}
}