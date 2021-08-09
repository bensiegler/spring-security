package org.springframework.security.authentication;

import org.springframework.security.core.GrantedAuthority;
import java.util.Collection;

/**
 *
 */
public class TwoFactorAuthenticationToken extends AbstractAuthenticationToken {

	private final Object principal;

	private String confirmed2FACode;

	private final Object credential;

	public TwoFactorAuthenticationToken(Object principal, Object credential, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.credential = credential;
		super.setAuthenticated(true);
	}

	public TwoFactorAuthenticationToken(Object principal, Object credential, String code) {
		super(null);
		this.confirmed2FACode = code;
		this.principal = principal;
		this.credential = credential;
	}

	public TwoFactorAuthenticationToken(Object principal, Object credential) {
		super(null);
		this.principal = principal;
		this.credential = credential;
	}

	@Override
	public Object getCredentials() {
		return credential;
	}

	@Override
	public Object getPrincipal() {
		return principal;
	}

	@Override
	public void setAuthenticated(boolean authenticated) {
		if(!super.isAuthenticated()) {
			throw new IllegalStateException("You cannot set this token to authenticated. Use the authorities constructor instead.");
		}
		super.setAuthenticated(authenticated);
	}
}
