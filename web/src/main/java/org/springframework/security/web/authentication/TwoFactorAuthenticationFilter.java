package org.springframework.security.web.authentication;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TwoFactorAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.twofa.dtos.TwoFactorAuthCodeWrapper;
import org.springframework.security.web.authentication.twofa.services.TwoFactorAuthCodeService;
import org.springframework.security.web.authentication.twofa.stategies.sendattemp.TwoFactorAuthCodeSendStrategy;
import org.springframework.security.web.authentication.twofa.stategies.sendfailure.TwoFactorAuthCodeSendFailureStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class TwoFactorAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
	public static final String DEFAULT_USERNAME_FORM_KEY = "username";
	public static final String DEFAULT_PASSWORD_FORM_KEY = "password";
	public static final String DEFAULT_CODE_FORM_KEY = "code";

	public static final String DEFAULT_TWO_FACTOR_PROCESSING_URL = "/2FA/authenticate";
	public static final String DEFAULT_LOGIN_REQUEST_URL = "/login";
	public static final String DEFAULT_CODE_RESEND_URL = "/2FA/resend";
	public static final String DEFAULT_TWO_FACTOR_FAILURE_URL = "/2FA?error";
	public static final String DEFAULT_TWO_FACTOR_REDIRECT_URL = "/2FA";

	protected String usernameFormKey = DEFAULT_USERNAME_FORM_KEY;
	protected String passwordFormKey = DEFAULT_PASSWORD_FORM_KEY;
	protected String twoFactorAuthCodeFormKey = DEFAULT_CODE_FORM_KEY;

    protected String twoFactorFailureUrl = DEFAULT_TWO_FACTOR_FAILURE_URL;
	protected String twoFactorRedirectUrl = DEFAULT_TWO_FACTOR_REDIRECT_URL;
	protected String loginRequestUrl = DEFAULT_LOGIN_REQUEST_URL;

	protected RequestMatcher twoFactorAuthenticationProcessingRequestMatcher
			= new AntPathRequestMatcher(DEFAULT_TWO_FACTOR_PROCESSING_URL, HttpMethod.POST.name());;
	protected RequestMatcher twoFactorAuthCodeResendRequestMatcher
			= new AntPathRequestMatcher(DEFAULT_CODE_RESEND_URL, HttpMethod.GET.name());
	protected static RequestMatcher loginRequestAntMatcher
			= new AntPathRequestMatcher(DEFAULT_LOGIN_REQUEST_URL, HttpMethod.POST.name());

	private TwoFactorAuthCodeService codeService;
	private TwoFactorAuthCodeSendStrategy sendStrategy;
	private UserDetailsService userDetailsService;
	private TwoFactorAuthCodeSendFailureStrategy sendFailureStrategy;

	public TwoFactorAuthenticationFilter() {
		super(loginRequestAntMatcher);
	}

	public TwoFactorAuthenticationFilter(AuthenticationManager manager) {
		super(loginRequestAntMatcher, manager);
	}

	public TwoFactorAuthenticationFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }

    public TwoFactorAuthenticationFilter(RequestMatcher requiresAuthenticationRequestMatcher, AuthenticationManager authenticationManager) {
        super(requiresAuthenticationRequestMatcher, authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
		//check if initial login processing request, two factor authentication processing request
    	if(super.requiresAuthenticationRequestMatcher.matches(request)) {
			//confirm username and password
			String username = getRequestUsername(request);
			String password = getRequestPassword(request);
			UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
			setDetails(token, request);
			Authentication authentication = super.getAuthenticationManager().authenticate(token);
			//assume using TwoFactorAuthenticationUserDetails. This is problematic. Get help.
			UserDetails userDetails = (UserDetails) authentication.getPrincipal();

			if(userDetails.isTwoFactorAuthEnabled()) {
				TwoFactorAuthCodeWrapper codeWrapper = codeService.generateCode(request, userDetails.getUsername());
				sendCode(request, userDetails, codeWrapper);
				response.sendRedirect(twoFactorRedirectUrl);
				return null;
			}else{
				return authentication;
			}

		}else if(twoFactorAuthenticationProcessingRequestMatcher.matches(request)){
    		String sessionId = request.getRequestedSessionId();
    		String submittedCode = getRequestTwoFactorCode(request);
			TwoFactorAuthenticationToken authenticationToken = new TwoFactorAuthenticationToken(sessionId, submittedCode);
			try {
				Authentication authentication =  super.getAuthenticationManager().authenticate(authenticationToken);
				codeService.cleanUp(sessionId);
				return authentication;
			}catch (AuthenticationException e) {
				response.sendRedirect(twoFactorFailureUrl);
				return null;
			}
		}else{
			if(codeService.isAwaitingCode(request.getRequestedSessionId())) {
				TwoFactorAuthCodeWrapper codeWrapper = codeService.getCode(request.getRequestedSessionId());
				UserDetails userDetails = userDetailsService.loadUserByUsername(codeWrapper.getUsername());
				sendCode(request, userDetails , codeWrapper);
			}else{
				response.sendRedirect(loginRequestUrl);
			}
			return null;
		}
    }

	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		if(request.getMethod().equals("POST")) {
			if(requiresAuthenticationRequestMatcher.matches(request)) {
				return true;
			} else if (twoFactorAuthenticationProcessingRequestMatcher.matches(request)) {
				return true;
			}
		}
		if(twoFactorAuthCodeResendRequestMatcher.matches(request)) {
			return true;
		}

		if (this.logger.isTraceEnabled()) {
			if(twoFactorAuthenticationProcessingRequestMatcher != null) {
				this.logger.trace(
						LogMessage.format("Dit not match request to %s or %s", requiresAuthenticationRequestMatcher, twoFactorAuthenticationProcessingRequestMatcher));
			}else {
				this.logger.trace(LogMessage.format("Did not match request to %s", requiresAuthenticationRequestMatcher));
			}
		}
		return false;
	}

	private void initiateTwoFactorAuthenticationProcedure(HttpServletRequest request, UserDetails userDetails) {

	}

	private void sendCode(HttpServletRequest request, UserDetails userDetails, TwoFactorAuthCodeWrapper codeWrapper) {
		try {
			sendStrategy.sendCode(userDetails, codeWrapper);
		}catch (Exception e) {
			sendFailureStrategy.handleSendFailure(codeWrapper, request);
		}
	}


	protected void setDetails(UsernamePasswordAuthenticationToken authRequest, HttpServletRequest request) {
		authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
	}

	private String getRequestUsername(HttpServletRequest request) {
    	String username = request.getParameter(usernameFormKey);
    	if(username == null) {
    		return "";
		}
    	return username;
	}

	private String getRequestTwoFactorCode(HttpServletRequest request) {
		String username = request.getParameter(twoFactorAuthCodeFormKey);
		if(username == null) {
			return "";
		}
		return username;
	}

	private String getRequestPassword(HttpServletRequest request) {
		String password = request.getParameter(passwordFormKey);
		if(password == null) {
			return "";
		}
		return password;
	}

	public String getUsernameFormKey() {
        return usernameFormKey;
    }

    public void setUsernameFormKey(String usernameFormKey) {
        this.usernameFormKey = usernameFormKey;
    }

    public String getPasswordFormKey() {
        return passwordFormKey;
    }

    public void setPasswordFormKey(String passwordFormKey) {
        this.passwordFormKey = passwordFormKey;
    }

	public String getTwoFactorAuthCodeFormKey() {
		return twoFactorAuthCodeFormKey;
	}

	public void setTwoFactorAuthCodeFormKey(String twoFactorAuthCodeFormKey) {
		this.twoFactorAuthCodeFormKey = twoFactorAuthCodeFormKey;
	}

	public void setCodeService(TwoFactorAuthCodeService codeService) {
		this.codeService = codeService;
	}

	public void setSendStrategy(TwoFactorAuthCodeSendStrategy sendStrategy) {
		this.sendStrategy = sendStrategy;
	}

	public void setSendFailureStrategy(TwoFactorAuthCodeSendFailureStrategy failureStrategy) {
		this.sendFailureStrategy = failureStrategy;
	}

	public void setTwoFactorFailureUrl(String twoFactorFailureUrl) {
		this.twoFactorFailureUrl = twoFactorFailureUrl;
	}

	public String getTwoFactorRedirectUrl() {
		return twoFactorRedirectUrl;
	}

	public void setTwoFactorRedirectUrl(String twoFactorRedirectUrl) {
		this.twoFactorRedirectUrl = twoFactorRedirectUrl;
	}

	/**
	 * Add a URL to respond to two factor authentication requests
	 * @param twoFactorProcessingUrl
	 */
	public void setTwoFactorProcessingUrl(String twoFactorProcessingUrl) {
		this.twoFactorAuthenticationProcessingRequestMatcher = new AntPathRequestMatcher(twoFactorProcessingUrl);
	}

	public String getLoginRequestUrl() {
		return loginRequestUrl;
	}
}
