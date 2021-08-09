package org.springframework.security.web.authentication.twofa.dtos;

import java.sql.Time;

public class SignInAttempt {

    private final String twoFactorCode;

    private final String sessionId;

    private final String username;

    private final Time time;

    public SignInAttempt(String sessionId, String twoFactorCode, String username, long time) {
        this.twoFactorCode = twoFactorCode;
        this.sessionId = sessionId;
        this.username = username;
        this.time = new Time(time);
    }

    public String getTwoFactorCode() {
    	if(null != twoFactorCode) {
			return twoFactorCode.trim();
		}

    	return null;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getUsername() {
        return username;
    }

    public Time getTime() {
        return time;
    }
}
