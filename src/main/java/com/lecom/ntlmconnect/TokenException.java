package com.lecom.ntlmconnect;

public class TokenException extends Exception {
	private byte[] responseToken;

	public TokenException(byte[] responseToken) {
		super();
		this.responseToken = responseToken;
	}

	/**
	 * @return the responseToken
	 */
	public byte[] getResponseToken() {
		return responseToken;
	}

	/**
	 * @param responseToken the responseToken to set
	 */
	public void setResponseToken(byte[] responseToken) {
		this.responseToken = responseToken;
	}
	
}
