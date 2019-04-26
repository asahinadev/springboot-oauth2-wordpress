package com.example.spring.wordpress.oauth2.user;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.oauth2.sdk.token.AccessToken;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class WordpressUser
		implements OAuth2User {

	@JsonIgnore
	AccessToken accessToken;

	@JsonAnySetter
	Map<String, Object> extraParameters = new HashMap<>();

	@JsonProperty(META)
	Map<String, Map<String, String>> meta = new HashMap<>();

	@JsonProperty(TOKEN_SCOPE)
	Set<String> tokenScope = new HashSet<>();

	@JsonProperty(ABTESTS)
	Map<String, Object> abtests = new HashMap<>();

	@JsonProperty(SOCIAL_LOGIN_CONNECTIONS)
	Set<String> socialLoginConnections = new HashSet<>();

	public static final String ID = "ID";
	public static final String DISPLAY_NAME = "display_name";
	public static final String USERNAME = "username";
	public static final String EMAIL = "email";
	public static final String PRIMARY_BLOG = "primary_blog";
	public static final String PRIMARY_BLOG_URL = "primary_blog_url";
	public static final String PRIMARY_BLOG_IS_JETPACK = "primary_blog_is_jetpack";
	public static final String LANGUAGE = "language";
	public static final String LOCALE_VARIANT = "locale_variant";
	public static final String TOKEN_SITE_ID = "token_site_id";
	public static final String TOKEN_SCOPE = "token_scope";
	public static final String AVATAR_URL = "avatar_URL";
	public static final String PROFILE_URL = "profile_URL";
	public static final String VERIFIED = "verified";
	public static final String EMAIL_VERIFIED = "email_verified";
	public static final String DATE = "date";
	public static final String SITE_COUNT = "site_count";
	public static final String VISIBLE_SITE_COUNT = "visible_site_count";
	public static final String HAS_UNSEEN_NOTES = "has_unseen_notes";
	public static final String NEWEST_NOTE_TYPE = "newest_note_type";
	public static final String PHONE_ACCOUNT = "phone_account";

	public static final String META = "meta";
	public static final String META__LINKS = "links";
	public static final String META__LINKS__SELF = "self";
	public static final String META__LINKS__HELP = "help";
	public static final String META__LINKS__SITE = "site";
	public static final String META__LINKS__FLAGS = "flags";

	public static final String IS_VALID_GOOGLE_APPS_COUNTRY = "is_valid_google_apps_country";
	public static final String USER_IP_COUNTRY_CODE = "user_ip_country_code";
	public static final String SOCIAL_LOGIN_CONNECTIONS = "social_login_connections";
	public static final String SOCIAL_SIGNUP_SERVICE = "social_signup_service";
	public static final String ABTESTS = "abtests";

	@Override
	@JsonIgnore
	public String getName() {
		return extraParameters.get(ID).toString();
	}

	@JsonIgnore
	public String getEmail() {
		return extraParameters.get(EMAIL).toString();
	}

	@JsonIgnore
	public Set<String> getTokenScope() {
		if (tokenScope == null) {
			return new HashSet<>();
		}
		return tokenScope;
	}

	@JsonIgnore
	public Map<String, Map<String, String>> getMeta() {
		if (meta == null) {
			return new HashMap<>();
		}
		return meta;
	}

	@JsonIgnore
	public Map<String, String> getMetaLinks() {
		String key = META__LINKS;
		if (getMeta().get(key) == null) {
			return new HashMap<>();
		}
		return getMeta().get(key);
	}

	@JsonIgnore
	public String getMetaLinks(String key) {
		return getMetaLinks(key);
	}

	@JsonIgnore
	public Map<String, Object> getAbtests() {
		if (abtests == null) {
			return new HashMap<>();
		}
		return abtests;
	}

	@JsonIgnore
	public Object getAbtests(String key) {
		return getAbtests().get(key);
	}

	public Set<String> getSocialLoginConnections() {
		if (socialLoginConnections == null) {
			return new HashSet<>();
		}
		return socialLoginConnections;
	}

	@Override
	@JsonIgnore
	public List<GrantedAuthority> getAuthorities() {
		return Arrays.asList(
				new OAuth2UserAuthority("USER", getAttributes()),
				new SimpleGrantedAuthority("USER"));
	}

	@Override
	@JsonIgnore
	public Map<String, Object> getAttributes() {
		Map<String, Object> attributes = new HashMap<>(extraParameters);

		attributes.put(META, getMeta());
		attributes.put(TOKEN_SCOPE, getTokenScope());
		attributes.put(ABTESTS, getAbtests());
		attributes.put(SOCIAL_LOGIN_CONNECTIONS, getSocialLoginConnections());

		return Collections.unmodifiableMap(attributes);
	}

	public String toString() {
		return getAttributes().toString();
	}

}
