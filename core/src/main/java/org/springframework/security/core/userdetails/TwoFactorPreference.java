package org.springframework.security.core.userdetails;

/**
 * A class used to store 2FA user preference information and to differentiate between codes
 * that need to be sent and codes that need to be generated.
 */
public class TwoFactorPreference {
	private boolean isKey;
	private String data;

	public TwoFactorPreference(boolean isKey, String data) {
		this.isKey = isKey;
		this.data = data;
	}

	public boolean isKey() {
		return isKey;
	}

	public void setKey(boolean key) {
		isKey = key;
	}

	public String getData() {
		return data;
	}

	public void setData(String data) {
		this.data = data;
	}
}
