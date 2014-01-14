package com.polytech.security;

import java.io.Serializable;

public class Frame implements Serializable {

	// static variable for 
	// Code Description References 
	// 1 Request. 
	static final byte CODE_REQUEST = 1;
	// 2 Response.
	static final byte CODE_RESPONSE = 2;
	// 3 Success. 
	static final byte CODE_SUCCESS = 3;
	// 4 Failure. 
	static final byte CODE_FAILURE = 4;

	// header 
	byte code;
	byte identifier;
	int length;
	Data data;
	
	public Frame() {}
	
	public Frame (byte code, byte identifier, Data data){
		this(code, identifier);
		this.data = data;
		this.length = data.data.length;
	}
	
	public Frame (byte code, byte identifier){
		this.code = code;
		this.identifier = identifier;
		
	}
	
	public String toString() {
		return "Frame {\n  code = " + code + "\n  id = " + identifier 
			+ "\n  length = " + length + "\n  data = "+ data +"\n}";
	}
}