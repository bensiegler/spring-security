package org.springframework.security.web.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TwoFactorAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.TwoFactorPreference;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.twofa.dtos.SignInAttempt;
import org.springframework.security.web.authentication.twofa.services.TotpService;
import org.springframework.security.web.authentication.twofa.services.TwoFactorAuthCodeService;

import java.util.HashMap;

public class TwoFactorAuthenticationProvider implements AuthenticationProvider {

	private TwoFactorAuthCodeService codeService;
	private UserDetailsService userDetailsService;
	private TotpService totpService;

	public TwoFactorAuthenticationProvider(TwoFactorAuthCodeService codeService, UserDetailsService userDetailsService, TotpService totpService) {
		this.codeService = codeService;
		this.userDetailsService = userDetailsService;
		this.totpService = totpService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String sessionId = (String) authentication.getPrincipal();
		String codeToCheck = (String) authentication.getCredentials();
		SignInAttempt signInAttempt = codeService.getCode(sessionId);
		UserDetails principal = userDetailsService.loadUserByUsername(signInAttempt.getUsername());

		if(null == signInAttempt.getTwoFactorCode()) {
			//two factor code provided by authenticator app
			HashMap<Integer, TwoFactorPreference> preferences = principal.getTwoFactorAuthPreferences();
			for(Integer i: preferences.keySet()) {
				TwoFactorPreference preference = preferences.get(i);
				if(preference.isKey()) {
					totpService.confirmCode(preference, codeToCheck);
				}
			}
		}else{
			//two factor code was sent
			if(codeToCheck.trim().equals(signInAttempt.getTwoFactorCode())) {
				if(codeService.isCodeExpired(signInAttempt)) {
					throw new BadCredentialsException("code is expired");
				}else{
					return createNewToken(principal);
				}
			} else {
				throw new BadCredentialsException("invalid code");
			}
		}

		principal.getTwoFactorAuthPreferences();

		return createNewToken(principal);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(TwoFactorAuthenticationToken.class);
	}

	public AbstractAuthenticationToken createNewToken(UserDetails principal) {
		return new TwoFactorAuthenticationToken(principal, null, principal.getAuthorities());
	}
}
