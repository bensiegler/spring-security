package org.springframework.security.config.annotation.web.configurers;

import org.springframework.cache.Cache;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.TwoFactorAuthenticationFilter;
import org.springframework.security.web.authentication.TwoFactorAuthenticationProvider;
import org.springframework.security.web.authentication.twofa.repositories.DatabaseTwoFactorAuthCodeRepository;
import org.springframework.security.web.authentication.twofa.repositories.InMemoryTwoFactorAuthCodeRepository;
import org.springframework.security.web.authentication.twofa.repositories.TwoFactorAuthCodeRepository;
import org.springframework.security.web.authentication.twofa.services.TotpService;
import org.springframework.security.web.authentication.twofa.services.TwoFactorAuthCodeServiceImpl;
import org.springframework.security.web.authentication.twofa.services.TwoFactorAuthCodeService;
import org.springframework.security.web.authentication.twofa.stategies.codegeneration.SixDigitAuthCodeGenerationStrategy;
import org.springframework.security.web.authentication.twofa.stategies.codegeneration.TwoFactorAuthCodeGenerationStrategy;
import org.springframework.security.web.authentication.twofa.stategies.sendattemp.TwoFactorAuthCodeSendStrategy;
import org.springframework.security.web.authentication.twofa.stategies.sendfailure.NullSendFailureStrategy;
import org.springframework.security.web.authentication.twofa.stategies.sendfailure.TwoFactorAuthCodeSendFailureStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import javax.sql.DataSource;

public final class TwoFactorLoginConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractAuthenticationFilterConfigurer<H, TwoFactorLoginConfigurer<H>, TwoFactorAuthenticationFilter> {

	private TwoFactorAuthCodeSendStrategy sendStrategy;
	private TwoFactorAuthCodeSendFailureStrategy sendFailureStrategy = new NullSendFailureStrategy();

	private String usernameFormKey;
	private String passwordFormKey;
	private String twoFactorAuthCodeFormKey;

	private TwoFactorAuthCodeService codeService;
	private TotpService totpService = new TotpService();
	private TwoFactorAuthCodeGenerationStrategy generationStrategy;
	private TwoFactorAuthCodeRepository codeRepository;
	private Long codeExpirationTime;

	private String twoFactorProcessingUrl = TwoFactorAuthenticationFilter.DEFAULT_TWO_FACTOR_PROCESSING_URL;
	private String twoFactorRedirectUrl = TwoFactorAuthenticationFilter.DEFAULT_TWO_FACTOR_REDIRECT_URL;
	private String twoFactorFailureUrl = TwoFactorAuthenticationFilter.DEFAULT_TWO_FACTOR_FAILURE_URL;

	private boolean addTwoFactorAuthenticationProvider = true;
	private UserDetailsService userDetailsService;

	public TwoFactorLoginConfigurer() {
		super(new TwoFactorAuthenticationFilter(), "/login");
	}

	@Override
	public void configure(H http) throws Exception {
		Assert.notNull(sendStrategy, "You must set a TwoFactorAuthenticationCodeSendStrategy for the TwoFactorAuthenticationFilter");
		Assert.notNull(codeRepository, "You must set a TwoFactorCodeRepository for the TwoFactorAuthenticationFilter");

		TwoFactorAuthenticationFilter filter = super.getAuthenticationFilter();

		filter.setSendStrategy(sendStrategy);
		filter.setSendFailureStrategy(sendFailureStrategy);

		if(usernameFormKey != null) {
			filter.setUsernameFormKey(usernameFormKey);
		}
		if(passwordFormKey != null) {
			filter.setPasswordFormKey(passwordFormKey);
		}
		if(twoFactorAuthCodeFormKey != null) {
			filter.setTwoFactorAuthCodeFormKey(twoFactorAuthCodeFormKey);
		}

		if(codeService == null) {
			codeService = new TwoFactorAuthCodeServiceImpl(codeRepository);
			if(codeExpirationTime != null) {
				codeService.setExpirationTime(codeExpirationTime);
			}
			if(generationStrategy != null) {
				codeService.setCodeGenerationStrategy(generationStrategy);
			}
		}
		filter.setCodeService(codeService);

		filter.setTwoFactorProcessingUrl(twoFactorProcessingUrl);
		filter.setTwoFactorRedirectUrl(twoFactorRedirectUrl);
		filter.setTwoFactorFailureUrl(twoFactorFailureUrl);
		filter.setLoginRequestUrl(getLoginPage());

		if(addTwoFactorAuthenticationProvider) {
			Assert.notNull(userDetailsService, "You must assign a UserDetailsService if not providing your own TwoFactorCodeAuthenticationProvider");
			ProviderManager manager = (ProviderManager) http.getSharedObject(AuthenticationManager.class);
			manager.getProviders().add(new TwoFactorAuthenticationProvider(codeService, userDetailsService, totpService));
		}
		super.configure(http);
	}

	@Override
	protected void updateAccessDefaults(H http) {
		if(super.isPermitAll()) {
			super.updateAccessDefaults(http);
			PermitAllSupport.permitAll(http, this.twoFactorProcessingUrl, this.twoFactorRedirectUrl, this.twoFactorFailureUrl);
		}
	}

	public TwoFactorCodeServiceConfigurer codeService() {
		return new TwoFactorCodeServiceConfigurer();
	}

	public TwoFactorLoginConfigurer<H> loginPage(String loginPageUrl) {
		super.loginPage(loginPageUrl);
		return TwoFactorLoginConfigurer.this;
	}

	public TwoFactorLoginConfigurer<H> totpService(TotpService service) {
		this.totpService = service;
		return TwoFactorLoginConfigurer.this;
	}

	public TwoFactorLoginConfigurer<H> codeService(TwoFactorAuthCodeService codeService) {
		this.codeService = codeService;
		return TwoFactorLoginConfigurer.this;
	}

	public TwoFactorLoginConfigurer<H> usernameFormKey(String key) {
		this.usernameFormKey = key;
		return TwoFactorLoginConfigurer.this;
	}

	public TwoFactorLoginConfigurer<H> passwordFormKey(String key) {
		this.passwordFormKey = key;
		return TwoFactorLoginConfigurer.this;
	}

	public TwoFactorLoginConfigurer<H> codeFormKey(String key) {
		this.twoFactorAuthCodeFormKey = key;
		return TwoFactorLoginConfigurer.this;
	}

	public TwoFactorLoginConfigurer<H> sendStrategy(TwoFactorAuthCodeSendStrategy sendStrategy) {
		this.sendStrategy = sendStrategy;
		return TwoFactorLoginConfigurer.this;
	}

	public TwoFactorLoginConfigurer<H> sendFailureStrategy(TwoFactorAuthCodeSendFailureStrategy failureStrategy) {
		this.sendFailureStrategy = failureStrategy;
		return TwoFactorLoginConfigurer.this;
	}

	public TwoFactorLoginConfigurer<H> twoFactorProcessingUrl(String url) {
		this.twoFactorProcessingUrl = url;
		return TwoFactorLoginConfigurer.this;
	}

	public TwoFactorLoginConfigurer<H> twoFactorRedirectUrl(String url) {
		this.twoFactorRedirectUrl = url;
		return TwoFactorLoginConfigurer.this;
	}

	public TwoFactorLoginConfigurer<H> twoFactorFailureUrl(String url) {
		this.twoFactorFailureUrl = url;
		return TwoFactorLoginConfigurer.this;
	}

	public TwoFactorLoginConfigurer<H> addTwoFactorAuthenticationProvider(boolean addProvider) {
		this.addTwoFactorAuthenticationProvider = addProvider;
		return TwoFactorLoginConfigurer.this;
	}

	public TwoFactorLoginConfigurer<H> userDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
		return TwoFactorLoginConfigurer.this;
	}

	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		return new AntPathRequestMatcher(loginProcessingUrl, HttpMethod.POST.name());
	}

	public class TwoFactorCodeServiceConfigurer {

		public TwoFactorLoginConfigurer<H> and() {
			return TwoFactorLoginConfigurer.this;
		}

		public TwoFactorCodeServiceConfigurer generationStrategy(TwoFactorAuthCodeGenerationStrategy generationStrategy) {
			TwoFactorLoginConfigurer.this.generationStrategy = generationStrategy;
			return TwoFactorCodeServiceConfigurer.this;
		}

		public TwoFactorCodeServiceConfigurer useSixDigitCodes() {
			TwoFactorLoginConfigurer.this.generationStrategy = new SixDigitAuthCodeGenerationStrategy();
			return TwoFactorCodeServiceConfigurer.this;
		}

		public TwoFactorCodeServiceConfigurer codeRepository(TwoFactorAuthCodeRepository codeRepository) {
			TwoFactorLoginConfigurer.this.codeRepository = codeRepository;
			return TwoFactorCodeServiceConfigurer.this;
		}

		public TwoFactorCodeServiceConfigurer expirationTime(long expirationTimeInMillis) {
			TwoFactorLoginConfigurer.this.codeExpirationTime = expirationTimeInMillis;
			return TwoFactorCodeServiceConfigurer.this;
		}

		public TwoFactorCodeServiceConfigurer inMemoryRepository(Cache cache) {
			TwoFactorLoginConfigurer.this.codeRepository = new InMemoryTwoFactorAuthCodeRepository(cache);
			return TwoFactorCodeServiceConfigurer.this;
		}

		public TwoFactorCodeServiceConfigurer databaseRepository(DataSource dataSource) {
			TwoFactorLoginConfigurer.this.codeRepository = new DatabaseTwoFactorAuthCodeRepository(dataSource);
			return TwoFactorCodeServiceConfigurer.this;
		}

		public TwoFactorCodeServiceConfigurer databaseRepository(DatabaseTwoFactorAuthCodeRepository codeRepository) {
			TwoFactorLoginConfigurer.this.codeRepository = codeRepository;
			return TwoFactorCodeServiceConfigurer.this;
		}
	}



}
