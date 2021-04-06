package org.springframework.security.web.authentication;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TwoFactorAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.twofa.dtos.TwoFactorAuthCodeWrapper;
import org.springframework.security.web.authentication.twofa.services.TwoFactorAuthCodeService;
import org.springframework.security.web.authentication.twofa.stategies.sendattemp.TwoFactorAuthCodeSendStrategy;
import org.springframework.security.web.authentication.twofa.stategies.sendfailure.TwoFactorAuthCodeSendFailureStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class TwoFactorAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	public static final AntPathRequestMatcher DEFAULT_LOGIN_REQUEST_ANT_MATCHER
			= new AntPathRequestMatcher("/login", HttpMethod.POST.name());
	public static final AntPathRequestMatcher DEFAULT_TWO_FACTOR_PROCESSING_ANT_MATCHER
			= new AntPathRequestMatcher("/2FA/authenticate", HttpMethod.POST.name());
	public static final AntPathRequestMatcher DEFAULT_TWO_FACTOR_CODE_RESEND_REQUEST_ANT_MATCHER
			= new AntPathRequestMatcher("/2FA/resend");
	public static final String DEFAULT_USERNAME_FORM_KEY = "username";
	public static final String DEFAULT_PASSWORD_FORM_KEY = "password";
	public static final String DEFAULT_CODE_FORM_KEY = "code";
	public static final String DEFAULT_TWO_FACTOR_FAILURE_URL = "/2FA?error";
	public static final String DEFAULT_TWO_FACTOR_REDIRECT_URL = "/2FA";

	private String usernameFormKey = DEFAULT_USERNAME_FORM_KEY;
    private String passwordFormKey = DEFAULT_PASSWORD_FORM_KEY;
    private String twoFactorAuthCodeFormKey = DEFAULT_CODE_FORM_KEY;

    protected String twoFactorFailureUrl = DEFAULT_TWO_FACTOR_FAILURE_URL;
	protected String twoFactorRedirectUrl = DEFAULT_TWO_FACTOR_REDIRECT_URL;
	protected RequestMatcher twoFactorAuthenticationProcessingRequestMatcher = DEFAULT_TWO_FACTOR_PROCESSING_ANT_MATCHER;
	protected RequestMatcher twoFactorAuthCodeResendMatcher =

	private TwoFactorAuthCodeService codeService;
	private TwoFactorAuthCodeSendStrategy sendStrategy;
	private TwoFactorAuthCodeSendFailureStrategy sendFailureStrategy;

	public TwoFactorAuthenticationFilter() {
		super(DEFAULT_LOGIN_REQUEST_ANT_MATCHER);
	}

	public TwoFactorAuthenticationFilter(AuthenticationManager manager) {
		super(DEFAULT_LOGIN_REQUEST_ANT_MATCHER, manager);
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
				initiateTwoFactorAuthenticationProcedure(request, userDetails);
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

		}
    }

	private void initiateTwoFactorAuthenticationProcedure(HttpServletRequest request, UserDetails userDetails) {
    	TwoFactorAuthCodeWrapper codeWrapper = codeService.generateCode(request, userDetails.getUsername());
    	try {
    		sendStrategy.sendCode(userDetails, codeWrapper);
		}catch (Exception e) {
    		sendFailureStrategy.handleSendFailure(codeWrapper, request);
		}
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

	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {

		if(request.getMethod().equals("POST")) {
			if(requiresAuthenticationRequestMatcher.matches(request)) {
				return true;
			} else if (twoFactorAuthenticationProcessingRequestMatcher.matches(request)) {
				return true;
			}
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
}
