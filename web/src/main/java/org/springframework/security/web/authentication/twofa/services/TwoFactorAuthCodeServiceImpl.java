package org.springframework.security.web.authentication.twofa.services;


import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.authentication.twofa.dtos.TwoFactorAuthCode;
import org.springframework.security.web.authentication.twofa.dtos.TwoFactorAuthCodeWrapper;
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
    public TwoFactorAuthCodeWrapper generateCode(HttpServletRequest request, String username) {
        Assert.notNull(request, "request cannot be null!");
        String sessionId = request.getRequestedSessionId();
        TwoFactorAuthCodeWrapper codeWrapper = new TwoFactorAuthCodeWrapper(sessionId, generateCodeString(), username, System.currentTimeMillis());
        repository.insertCode(codeWrapper);
        return codeWrapper;
    }

    @Override
    public TwoFactorAuthCodeWrapper validateCode(String codeToCheck, String sessionId) throws BadCredentialsException {
        TwoFactorAuthCodeWrapper realCode = repository.getCode(sessionId);

        if(isCodeExpired(realCode)) {
			throw new BadCredentialsException("The 2FA code has expired");
		}
        if(doCodesMatch(codeToCheck, realCode)) {
			throw new BadCredentialsException("That 2FA code is invalid!");
		}

		return realCode;
    }

    @Override
    public void cleanUp(String sessionId) {
        repository.removeCode(sessionId);
    }

    public boolean isAwaitingCode(String sessionId) {
    	TwoFactorAuthCodeWrapper wrapper = repository.getCode(sessionId);
    	if(wrapper != null) {
    		if(!isCodeExpired(wrapper)) {
				return true;
			}
    		//get codes by username check to make sure all expired codes for this user are removed. This is where housekeeping happens.
    		repository.removeCode(sessionId);
		}
    	return false;
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


	private TwoFactorAuthCode generateCodeString() {
		return new TwoFactorAuthCode(generationStrategy.generateCode());
	}

	private boolean doCodesMatch(String codeToCheck, TwoFactorAuthCodeWrapper realCode) {
		return codeToCheck.equals(realCode.getTwoFactorCode());
	}

	private boolean isCodeExpired(TwoFactorAuthCodeWrapper realCode) throws BadCredentialsException {
		return realCode.getTimeCreated().getTime() + expirationTimeInMillis < System.currentTimeMillis();
	}

}
