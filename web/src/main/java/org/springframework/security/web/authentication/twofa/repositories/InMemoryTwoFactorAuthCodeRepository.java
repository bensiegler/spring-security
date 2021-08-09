package org.springframework.security.web.authentication.twofa.repositories;

import org.springframework.cache.Cache;
import org.springframework.security.web.authentication.twofa.dtos.SignInAttempt;
import org.springframework.util.Assert;

public class InMemoryTwoFactorAuthCodeRepository implements TwoFactorAuthCodeRepository {

    private Cache cache;

    public InMemoryTwoFactorAuthCodeRepository(Cache cache) {
        this.cache = cache;
    }

    public void setCache(Cache cache) {
        Assert.notNull(cache, "The cache cannot be null");
        this.cache = cache;
    }

    @Override
    public void insertCode(SignInAttempt code) {
        cache.put(code.getSessionId(), code);
    }

    @Override
    public SignInAttempt getCode(String sessionId) {
        if(sessionId == null) {
            return null;
        }

        return cache.get(sessionId, SignInAttempt.class);
    }

    @Override
    public void removeCode(SignInAttempt code) {
        removeCode(code.getSessionId());
    }

    @Override
    public void removeCode(String sessionId) {
        cache.evict(sessionId);
    }
}
