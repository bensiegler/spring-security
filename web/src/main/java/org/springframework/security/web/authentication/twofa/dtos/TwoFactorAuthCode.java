package org.springframework.security.web.authentication.twofa.dtos;

public final class TwoFactorAuthCode {

    private final String twoFactorCode;

    public TwoFactorAuthCode(String twoFactorCode) {
        this.twoFactorCode = twoFactorCode.trim();
    }

    public String getCode() {
        return twoFactorCode;
    }
}
