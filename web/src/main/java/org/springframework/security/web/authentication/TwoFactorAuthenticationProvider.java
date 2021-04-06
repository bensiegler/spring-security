package org.springframework.security.web.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.TwoFactorAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.twofa.dtos.TwoFactorAuthCodeWrapper;
import org.springframework.security.web.authentication.twofa.services.TwoFactorAuthCodeService;

public class TwoFactorAuthenticationProvider implements AuthenticationProvider {

	private TwoFactorAuthCodeService codeService;
	private UserDetailsService userDetailsService;

	public TwoFactorAuthenticationProvider(TwoFactorAuthCodeService codeService, UserDetailsService userDetailsService) {
		this.codeService = codeService;
		this.userDetailsService = userDetailsService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String sessionId = (String) authentication.getPrincipal();
		String codeToCheck = (String) authentication.getCredentials();
		TwoFactorAuthCodeWrapper codeWrapper = codeService.validateCode(codeToCheck, sessionId);

		UserDetails principal = userDetailsService.loadUserByUsername(codeWrapper.getUsername());
		return new TwoFactorAuthenticationToken(principal, null, principal.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(TwoFactorAuthenticationToken.class);
	}

	public void setCodeService(TwoFactorAuthCodeService codeService) {
		this.codeService = codeService;
	}

	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}
}
