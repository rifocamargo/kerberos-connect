package com.lecom.ntlmconnect;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.kerberos.authentication.KerberosAuthenticationProvider;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.KerberosTicketValidator;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosClient;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.kerberos.web.authentication.SpnegoEntryPoint;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.security.ui.ntlm.NtlmAuthenticationFilter;
import org.springframework.security.ui.ntlm.NtlmAuthenticationFilterEntryPoint;
import org.springframework.security.ui.ntlm.ldap.authenticator.NtlmAwareLdapAuthenticator;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.savedrequest.NullRequestCache;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${app.ad-domain}")
	private String adDomain;

	@Value("${app.ad-server}")
	private String adServer;

	@Value("${app.service-principal}")
	private String servicePrincipal;

	@Value("${app.keytab-location}")
	private String keytabLocation;

	@Value("${app.ldap-search-base}")
	private String ldapSearchBase;

	@Value("${app.ldap-search-filter}")
	private String ldapSearchFilter;

	@Autowired
	private ContextSource contextSource;

	@Value("${spring.ldap.custom.user-dn-patterns}={0}")
	private String userDnPatterns;

	@Autowired
	private DefaultLdapAuthoritiesPopulator defaultLdapAuthoritiesPopulator;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.exceptionHandling().authenticationEntryPoint(spnegoEntryPoint()).and().authorizeRequests()
				.antMatchers("/", "/home").permitAll().anyRequest().authenticated().and().formLogin()
				.loginPage("/login").permitAll().and().logout().permitAll().and()
				.addFilterBefore(spnegoAuthenticationProcessingFilter(), BasicAuthenticationFilter.class);
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(kerberosAuthenticationProvider())
				.authenticationProvider(kerberosServiceAuthenticationProvider())
				.userDetailsService(this.ldapUserDetailsService());

		auth.ldapAuthentication().ldapAuthoritiesPopulator(defaultLdapAuthoritiesPopulator)
				.userSearchFilter(userDnPatterns).contextSource((LdapContextSource) contextSource);
	}

	@Bean
	public DefaultLdapAuthoritiesPopulator getDefaultLdapAuthoritiesPopulator(ContextSource contextSource) {
		DefaultLdapAuthoritiesPopulator defaultLdapAuthoritiesPopulator = new DefaultLdapAuthoritiesPopulator(
				contextSource, "");
		defaultLdapAuthoritiesPopulator.setIgnorePartialResultException(true);
		return defaultLdapAuthoritiesPopulator;
	}

	@Bean
	public KerberosAuthenticationProvider kerberosAuthenticationProvider() throws Exception {
		KerberosAuthenticationProvider provider = new KerberosAuthenticationProvider();
		SunJaasKerberosClient client = new SunJaasKerberosClient();
		client.setDebug(true);
		provider.setKerberosClient(client);
		provider.setUserDetailsService(this.userDetailsServiceBean());
		return provider;
	}

	@Bean
	public SpnegoEntryPoint spnegoEntryPoint() {
		return new SpnegoEntryPoint("/login");
	}

	@Bean
	public SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter() throws Exception {
		SpnegoAuthenticationProcessingFilter filter = new SpnegoAuthenticationProcessingFilter();
		filter.setAuthenticationManager(authenticationManagerBean());
		return filter;
	}

	@Bean
	public KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider() {
		KerberosServiceAuthenticationProvider provider = new KerberosServiceAuthenticationProvider();
		provider.setTicketValidator(sunJaasKerberosTicketValidator());
		provider.setUserDetailsService(ldapUserDetailsService());
		return provider;
	}

	@Bean
	public KerberosTicketValidator sunJaasKerberosTicketValidator() {
		SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
		ticketValidator.setServicePrincipal(servicePrincipal);
		ticketValidator.setKeyTabLocation(new FileSystemResource(keytabLocation));
		ticketValidator.setDebug(true);
		return ticketValidator;
	}

	// @Bean
	// public KerberosLdapContextSource kerberosLdapContextSource() {
	// KerberosLdapContextSource contextSource = new
	// KerberosLdapContextSource(adServer);
	// contextSource.setUserDn(servicePrincipal);
	// contextSource.setPassword("L3c0m@2017");
	// contextSource.setLoginConfig(loginConfig());
	// return contextSource;
	// }
	//
	// @Bean
	// public SunJaasKrb5LoginConfig loginConfig() {
	// SunJaasKrb5LoginConfig loginConfig = new SunJaasKrb5LoginConfig();
	// loginConfig.setKeyTabLocation(new FileSystemResource(keytabLocation));
	// loginConfig.setServicePrincipal(servicePrincipal);
	// loginConfig.setDebug(true);
	// loginConfig.setUseTicketCache(true);
	// loginConfig.setIsInitiator(false);
	// return loginConfig;
	// }

	@Bean
	public LdapUserDetailsService ldapUserDetailsService() {
		FilterBasedLdapUserSearch userSearch = new FilterBasedLdapUserSearch(ldapSearchBase, ldapSearchFilter,
				(LdapContextSource) contextSource);
		LdapUserDetailsService service = new LdapUserDetailsService(userSearch);
		service.setUserDetailsMapper(new LdapUserDetailsMapper());
		return service;
	}

}
