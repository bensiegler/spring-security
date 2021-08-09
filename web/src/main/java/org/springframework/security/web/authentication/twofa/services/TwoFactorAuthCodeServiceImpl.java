package org.springframework.security.web.authentication.twofa.services;


import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.authentication.twofa.dtos.SignInAttempt;
import org.springframework.security.web.authentication.twofa.repositories.TwoFactorAuthCodeRepository;
import org.springframework.security.web.authentication.twofa.stategies.codegeneration.SixDigitAuthCodeGenerationStrategy;
import org.springframework.security.web.authentication.twofa.stategies.codegeneration.TwoFactorAuthCodeGenerationStrategy;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;

public class TwoFactorAuthCodeServiceImpl implements TwoFactorAuthCodeService {
	private final static long DEFAULT_EXPIRATION_TIME_IN_MILLIS = 90000;
	private final static TwoFactorAuthCodeGenerationStrategy DEFAULT_GENERATION_STRATEGY = new SixDigitAuthCodeGenerationStrategy();

    private TwoFactorAuthCodeGenerationStrategy generationStrategy = DEFAULT_GENERATION_STRATEGY;
    private long expirationTimeInMillis = DEFAULT_EXPIRATION_TIME_IN_MILLIS;
    private TwoFactorAuthCodeRepository repository;

    public TwoFactorAuthCodeServiceImpl(TwoFactorAuthCodeRepository repository) {
        Assert.notNull(repository, "repository cannot be null");
        this.repository = repository;
    }

    @Override
    public String generateCode(HttpServletRequest request, String username) {
        return generateCodeString();
    }

    public SignInAttempt saveAttempt(HttpServletRequest request, String username, String twoFactorCode) {
		Assert.notNull(request, "request cannot be null!");
		SignInAttempt attempt = new SignInAttempt(request.getRequestedSessionId(), twoFactorCode, username, System.currentTimeMillis());
    	repository.insertCode(attempt);
    	return attempt;
	}

    @Override
    public SignInAttempt getCode(String sessionId)  {
    	return repository.getCode(sessionId);
	}

    @Override
    public void cleanUp(String sessionId) {
        repository.removeCode(sessionId);
    }

    @Override
    public void setCodeRepository(TwoFactorAuthCodeRepository repository) {
        this.repository = repository;
    }

	@Override
	public void setCodeGenerationStrategy(TwoFactorAuthCodeGenerationStrategy generationStrategy) {
		this.generationStrategy = generationStrategy;
	}

	@Override
	public void setExpirationTime(long expirationTimeInMillis) {
		this.expirationTimeInMillis = expirationTimeInMillis;
	}

	@Override
	public String getUsernameFromSessionId(String sessionId) {
		return repository.getCode(sessionId).getUsername();
	}

	@Override
	public boolean isStepOneComplete(String sessionId) {
		SignInAttempt wrapper = repository.getCode(sessionId);

		if(null == wrapper) {
			return false;
		}

		return !isCodeExpired(wrapper);
	}

	private String generateCodeString() {
		return generationStrategy.generateCode();
	}

	public boolean isCodeExpired(SignInAttempt realCode) throws BadCredentialsException {
		return realCode.getTime().getTime() + expirationTimeInMillis < System.currentTimeMillis();
	}

}
