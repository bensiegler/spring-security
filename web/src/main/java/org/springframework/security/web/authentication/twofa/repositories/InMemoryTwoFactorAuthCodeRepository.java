package org.springframework.security.web.authentication.twofa.repositories;

import org.springframework.cache.Cache;
import org.springframework.security.web.authentication.twofa.dtos.SignInAttempt;
import org.springframework.util.Assert;

import java.util.HashMap;

public class InMemoryTwoFactorAuthCodeRepository implements TwoFactorAuthCodeRepository {

    private final HashMap<String, SignInAttempt> signInAttempts = new HashMap<>();

    @Override
    public void insertCode(SignInAttempt code) {
        signInAttempts.put(code.getSessionId(), code);
    }

    @Override
    public SignInAttempt getCode(String sessionId) {
        if(sessionId == null) {
            return null;
        }

        return signInAttempts.get(sessionId);
    }

    @Override
    public void removeCode(SignInAttempt code) {
        removeCode(code.getSessionId());
    }

    @Override
    public void removeCode(String sessionId) {
        signInAttempts.remove(sessionId);
    }
}
