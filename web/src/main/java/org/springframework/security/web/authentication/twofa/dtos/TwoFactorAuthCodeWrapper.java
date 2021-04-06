package org.springframework.security.web.authentication.twofa.dtos;

import java.sql.Time;

public class TwoFactorAuthCodeWrapper {

    private final TwoFactorAuthCode twoFactorCode;

    private final String sessionId;

    private final String username;

    private final Time timeCreated;

    public TwoFactorAuthCodeWrapper(String sessionId, TwoFactorAuthCode twoFactorCode, String username, long timeCreated) {
        this.twoFactorCode = twoFactorCode;
        this.sessionId = sessionId;
        this.username = username;
        this.timeCreated = new Time(timeCreated);
    }

    public String getTwoFactorCode() {
        return twoFactorCode.getCode();
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getUsername() {
        return username;
    }

    public Time getTimeCreated() {
        return timeCreated;
    }
}
