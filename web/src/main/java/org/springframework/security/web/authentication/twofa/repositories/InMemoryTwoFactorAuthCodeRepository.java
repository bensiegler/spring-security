package org.springframework.security.web.authentication.twofa.repositories;

import org.springframework.cache.Cache;
import org.springframework.security.web.authentication.twofa.dtos.TwoFactorAuthCodeWrapper;
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
    public void insertCode(TwoFactorAuthCodeWrapper code) {
        cache.put(code.getSessionId(), code);
    }

    @Override
    public TwoFactorAuthCodeWrapper getCode(String sessionId) {
        if(sessionId == null) {
            return null;
        }

        return cache.get(sessionId, TwoFactorAuthCodeWrapper.class);
    }

    @Override
    public void removeCode(TwoFactorAuthCodeWrapper code) {
        removeCode(code.getSessionId());
    }

    @Override
    public void removeCode(String sessionId) {
        cache.evict(sessionId);
    }
}
