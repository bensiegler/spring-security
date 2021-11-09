package org.springframework.security.web.authentication;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TwoFactorAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.TwoFactorPreference;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.twofa.dtos.SignInAttempt;
import org.springframework.security.web.authentication.twofa.services.TwoFactorAuthCodeService;
import org.springframework.security.web.authentication.twofa.stategies.sendattemp.TwoFactorAuthCodeSendStrategy;
import org.springframework.security.web.authentication.twofa.stategies.sendfailure.TwoFactorAuthCodeSendFailureStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

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
	public static final String DEFAULT_TWO_FACTOR_CHOICE_URL = "/2FA/choice";

	protected String usernameFormKey = DEFAULT_USERNAME_FORM_KEY;
	protected String passwordFormKey = DEFAULT_PASSWORD_FORM_KEY;
	protected String twoFactorAuthCodeFormKey = DEFAULT_CODE_FORM_KEY;

    protected String twoFactorFailureUrl = DEFAULT_TWO_FACTOR_FAILURE_URL;
    protected String twoFactorChoiceUrl = DEFAULT_TWO_FACTOR_CHOICE_URL;
	protected String twoFactorRedirectUrl = DEFAULT_TWO_FACTOR_REDIRECT_URL;
	protected String loginRequestUrl = DEFAULT_LOGIN_REQUEST_URL;

	protected RequestMatcher twoFactorAuthenticationProcessingRequestMatcher
			= new AntPathRequestMatcher(DEFAULT_TWO_FACTOR_PROCESSING_URL, HttpMethod.POST.name());
	protected RequestMatcher twoFactorAuthCodeResendRequestMatcher
			= new AntPathRequestMatcher(DEFAULT_CODE_RESEND_URL, HttpMethod.GET.name());
	protected static RequestMatcher loginRequestMatcher
			= new AntPathRequestMatcher(DEFAULT_LOGIN_REQUEST_URL, HttpMethod.POST.name());

	private TwoFactorAuthCodeSendStrategy sendStrategy;
	private TwoFactorAuthCodeSendFailureStrategy sendFailureStrategy;

	private TwoFactorAuthCodeService codeService;
	private UserDetailsService userDetailsService;

	//TODO make sure to set this up
	private AuthenticationFailureHandler failureHandler;

	public TwoFactorAuthenticationFilter() {
		super(loginRequestMatcher);
	}

	public TwoFactorAuthenticationFilter(AuthenticationManager manager) {
		super(loginRequestMatcher, manager);
	}

	public TwoFactorAuthenticationFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }

    public TwoFactorAuthenticationFilter(RequestMatcher requiresAuthenticationRequestMatcher, AuthenticationManager authenticationManager) {
        super(requiresAuthenticationRequestMatcher, authenticationManager);
    }

	/**
	 * This method dictates the two factor authentication flow. It handles 3 types of requests:
	 * <ol>
	 *   <li>
	 *		An initial username & password login request. When a request is received that matches the given <tt>loginRequestMatcher</tt>,
	 *		request processing is delegated to <tt>handleUsernamePasswordLogin</tt>.
	 *  </li>
	 *  <li>
	 *      A secondary request to check the provided two factor authentication code. When a request
	 *      matching <tt>twoFactorAuthenticationProcessingRequestMatcher</tt>, two factor authentication code processing
	 *      is delegated to <tt>handleTwoFactorAuthenticationLogin</tt>.
	 *  </li>
	 *  <li>
	 *      A two factor code resend request. When this type of request is received, the session ID is used to retrieve
	 *      the current code. If the code exists, it is resent, if it does not or the code is expired, the user is redirected
	 *      to the specified login page.
	 *  </li>
	 * </ol>
	 * @param request from which to extract parameters and perform the authentication
	 * @param response the response, which may be needed if the implementation has to do a
	 * redirect as part of a multi-stage authentication process (such as OpenID).
	 * @return A valid Authentication token or null when a further authentication/a redirect is required.
	 * @throws AuthenticationException is thrown in when there is a problem with the credentials provided, such as an incorrect password
	 * or a locked account.
	 * @throws IOException is thrown when there is a problem with the HttpServletResponse redirects.
	 */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
    	if(super.requiresAuthenticationRequestMatcher.matches(request)) {
			return handleUsernamePasswordLogin(request, response);
		}else if(twoFactorAuthenticationProcessingRequestMatcher.matches(request)) {
    		return handleTwoFactorAuthenticationLogin(request, response);
		}else if(twoFactorAuthCodeResendRequestMatcher.matches(request)) {
			if(codeService.isStepOneComplete(request.getRequestedSessionId())) {
				SignInAttempt codeWrapper = codeService.getCode(request.getRequestedSessionId());
				UserDetails userDetails = userDetailsService.loadUserByUsername(codeWrapper.getUsername());
				sendCode(request, userDetails, codeWrapper);
			}else{
				response.sendRedirect(loginRequestUrl);
			}
		}
		//TODO make sure you actually want to return null
		return null;
    }

	/**
	 *
	 * @param request
	 * @param response
	 * @return
	 */
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

	/**
	 * This method is invoked when a request matching <tt>requiresAuthenticationRequestMatcher</tt> is received.
	 * It proceeds by parsing the username & password received in the HTTP form. It then checks the credentials using
	 * the pre-defined <tt>AuthenticationManager</tt>.
	 *
	 * If the <tt>AuthenticationManager</tt> throws an exception it is passed back up the stack to the <tt>attemptAuthentication</tt>
	 * method. Whereas, if the authentication returns a valid Authentication token, the two factor authentication flow begins.
	 * The <tt>UserDetails</tt> object returned from the <tt>AuthenticationManager</tt> is checked to see if the user has enabled
	 * two factor authentication. If 2FA is on, the code is generated, sent and null is returned. If 2FA is off, the valid
	 * <tt>UsernamePasswordAuthenticationToken</tt> is returned.
	 * @param request used to retrieve information required for authentication
	 * @param response used to control redirect behavior.
	 * @return null if authentication is incomplete (code has been sent) or a valid Authentication token
	 * @throws IOException if an input-output problem occurs
	 */
    private Authentication handleUsernamePasswordLogin(HttpServletRequest request, HttpServletResponse response) throws IOException {
    	//redirect to 2FA code page if user is already awaiting valid code
		//TODO change isUserAwaitingCode() to show sign in attempts not only codes sent. This is for auth app integration.
    	if(codeService.isStepOneComplete(request.getRequestedSessionId())) {
    		response.sendRedirect(twoFactorChoiceUrl);
    		return null;
		}

		//confirm username and password
		String username = getRequestUsername(request);
		String password = getRequestPassword(request);
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
		token.setDetails(this.authenticationDetailsSource.buildDetails(request));
		Authentication authentication = super.getAuthenticationManager().authenticate(token);

		UserDetails userDetails = (UserDetails) authentication.getPrincipal();

		if(userDetails.isTwoFactorAuthEnabled()) {
			TwoFactorPreference primaryPreference = userDetails.getTwoFactorAuthPreferences().get(1);

			//TODO!!! must add login attempt
//			if (!primaryPreference.isKey()) {
//				//if first code is not TOTP: generate and send
//				String code = codeService.generateCode(request, userDetails.getUsername());
//				sendCode(request, userDetails, codeService.saveAttempt(request, username, code));
//			}else{
//				codeService.saveAttempt(request, username, null);
//			}

			response.sendRedirect(twoFactorChoiceUrl);
			return null;
		}else{
			return authentication;
		}
	}

	/**
	 * The handleTwoFactorAuthenticationLogin is defines the behavior for confirming two factor authentication codes.
	 * It is invoked by the <tt>attemptAuthentication</tt> method when a request matching the
	 * <tt>twoFactorAuthenticationProcessingRequestMatcher</tt> is received.
	 *
	 * At this point, a code should already have been sent. If not, the request is redirected to the login page and null is returned.
	 * If a code has already been sent, the code is retrieved from the <tt>TwoFactorAuthCodeService</tt> and a TwoFactorAuthenticationToken
	 * is created. The token is passed to the <tt>AuthenticationManager</tt> for checking.
	 *
	 * If the code matches, the method will call <tt>cleanUp</tt> and return the valid token. If they do not a TwoFactorFailureHandler is
	 * invoked.
	 * @param request used to retrieve information required for authentication
	 * @param response used to control redirect behavior.
	 * @return an authenticated Authentication token
	 * @throws IOException when a input-output problem occurs
	 * @throws AuthenticationException thrown when the provided code does not match the generated code.
	 */
	private Authentication handleTwoFactorAuthenticationLogin(HttpServletRequest request, HttpServletResponse response) throws IOException {
		String sessionId = request.getRequestedSessionId();
		String submittedCode = getRequestTwoFactorCode(request);

		if(!codeService.isStepOneComplete(sessionId)) {
			//redirect to login page if user did not already do step 1
			response.sendRedirect(loginRequestUrl);
			return null;
		}

		TwoFactorAuthenticationToken authenticationToken = new TwoFactorAuthenticationToken(sessionId, submittedCode);
		try {
			Authentication authentication =  super.getAuthenticationManager().authenticate(authenticationToken);
			codeService.cleanUp(sessionId);
//			TODO response.sendRedirect(super.getSuccessHandler());
			return authentication;
		}catch (AuthenticationException e) {
			//TODO start adding more failure handlers for customization
			response.sendRedirect(twoFactorFailureUrl);
			return null;
		}
	}

	/**
	 *
	 * @param request
	 * @param userDetails
	 * @param codeWrapper
	 */
	private void sendCode(HttpServletRequest request, UserDetails userDetails, SignInAttempt codeWrapper) {
		try {
			sendStrategy.sendCode(userDetails, codeWrapper);
		}catch (Exception e) {
			sendFailureStrategy.handleSendFailure(codeWrapper, request);
		}
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

	public void setLoginRequestUrl(String loginRequestUrl) {
		this.loginRequestUrl = loginRequestUrl;
	}
}
