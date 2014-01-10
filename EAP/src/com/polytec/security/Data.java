package com.polytec.security;

public class Data {

	// Type
	// 1 Identity. 
	static final byte TYPE_IDENTITY = 1;
	// 2 Notification. 
	static final byte TYPE_NOTIFICATION = 2;
	// 3 Nak (Response only). 
	static final byte TYPE_NAK = 3;
	// 4 MD5-Challenge.  
	static final byte TYPE_MD5_CHALLENGE = 4;
	// 4 MD5-Challenge.  
	static final byte TYPE_TLS_CHALLENGE = 5;

	// type
	byte type;
	// data
	byte[] data;

}