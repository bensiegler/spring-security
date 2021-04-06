package org.springframework.security.web.authentication.twofa.stategies.sendfailure;

import org.springframework.security.web.authentication.twofa.dtos.TwoFactorAuthCodeWrapper;

import javax.servlet.http.HttpServletRequest;

public class NullSendFailureStrategy implements TwoFactorAuthCodeSendFailureStrategy {
	@Override
	public void handleSendFailure(TwoFactorAuthCodeWrapper codeWrapper, HttpServletRequest request) {

	}
}
