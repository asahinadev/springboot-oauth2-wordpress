package com.example.spring.wordpress.oauth.user;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class WordpressUser
		implements OAuth2User {

	@JsonAnySetter
	Map<String, Object> extraParameters = new HashMap<>();

	@JsonIgnore
	public String getId() {
		return String.valueOf(getExtraParameters().get("ID"));
	}

	public String getDisplayName() {
		return String.valueOf(getExtraParameters().get("display_name"));
	}

	public String getUsername() {
		return String.valueOf(getExtraParameters().get("username"));
	}

	public String getEmail() {
		return String.valueOf(getExtraParameters().get("email"));
	}

	@Override
	@JsonIgnore
	public String getName() {
		return getId();
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
		return this.getExtraParameters();
	}

	public String toString() {
		return getExtraParameters().toString();
	}

}
