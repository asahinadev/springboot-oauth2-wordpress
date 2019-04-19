package com.example.spring.wordpress.oauth.token;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AccessTokenResponseClient
		implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

	private RestTemplate client;

	public AccessTokenResponseClient() {
		this.client = new RestTemplate(Arrays.asList(
				new FormHttpMessageConverter(),
				new MappingJackson2HttpMessageConverter(),
				new OAuth2AccessTokenResponseHttpMessageConverter()));
		this.client.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
	}

	public AccessTokenResponseClient(RestTemplate client) {
		this.client = client;
	}

	public OAuth2AccessTokenResponse getTokenResponse(
			OAuth2AuthorizationCodeGrantRequest request)
			throws OAuth2AuthenticationException {

		ClientRegistration clientRegistration = request.getClientRegistration();
		OAuth2AuthorizationExchange authorization = request.getAuthorizationExchange();
		ProviderDetails provider = clientRegistration.getProviderDetails();

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();

		parameters.add("grant_type", clientRegistration.getAuthorizationGrantType().getValue());
		parameters.add("client_id", clientRegistration.getClientId());
		parameters.add("client_secret", clientRegistration.getClientSecret());
		parameters.add("code", authorization.getAuthorizationResponse().getCode());
		parameters.add("redirect_uri", authorization.getAuthorizationRequest().getRedirectUri());
		// parameters.add("scope", String.join(" ", request.getClientRegistration().getScopes()));

		log.debug("parameters => {}", parameters);

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		headers.setAccept(Arrays.asList(
				MediaType.APPLICATION_JSON_UTF8));

		switch (clientRegistration.getRegistrationId()) {

		case "dropbox":
			// Basic 認証
			headers.setBasicAuth(
					clientRegistration.getClientId(),
					clientRegistration.getClientSecret());

			parameters.remove("client_id");
			parameters.remove("client_secret");
			break;

		default:
			break;
		}

		String uri = provider.getTokenUri();

		ResponseEntity<AccessTokenResponce> response = client.exchange(
				uri,
				HttpMethod.POST,
				new HttpEntity<>(parameters, headers),
				AccessTokenResponce.class);

		log.debug("{}", response);

		AccessTokenResponce token = response.getBody();

		log.debug("{}", token);

		Set<String> scopes = token.getScopes().isEmpty()
				? authorization.getAuthorizationRequest().getScopes()
				: token.getScopes();

		TokenType tokenType = token.getOauthTOkenType();

		switch (clientRegistration.getRegistrationId()) {

		case "linkedin":
			tokenType = TokenType.BEARER;
			break;

		default:
			break;

		}
		long expiresIn = token.getExpiresIn();
		if (expiresIn == 0) {
			expiresIn = 30000;
		}

		Map<String, Object> additionalParameters = new HashMap<>(token.getAttributes());

		switch (clientRegistration.getRegistrationId()) {

		case "dropbox":
			additionalParameters.put("account_id", token.getAccountId());
			break;

		case "wordpress":
			// additionalParameters.put("blog_id", token.getBlogId());
			break;

		default:
			break;
		}

		return OAuth2AccessTokenResponse.withToken(
				token.getAccessToken())
				.tokenType(tokenType)
				.expiresIn(expiresIn)
				.scopes(scopes)
				.additionalParameters(additionalParameters)
				.build();
	}
}