package com.example.spring.wordpress.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

import com.example.spring.wordpress.oauth2.user.WordpressUser;

@Configuration
@EnableWebSecurity
public class SecurityConfig
		extends WebSecurityConfigurerAdapter {

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/webjars/**", "/assets/**");
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		super.configure(auth);
	}

	@Override
	protected void configure(HttpSecurity http)
			throws Exception {
		http
				// 認証情報
				.authorizeRequests()
				.anyRequest().authenticated().and()

				// 認証は SSO オンリー
				.httpBasic().disable()
				.formLogin().disable()
				.logout().disable()

				// 認証関連ページは CSRF 対象外
				.csrf().ignoringAntMatchers(
						"/login",
						"/login/**",
						"/sso/**",
						"/oauth/**",
						"/oauth1/**",
						"/oauth2/**")
				.csrfTokenRepository(new HttpSessionCsrfTokenRepository()).and()

				// ユーザー情報エンドポイント
				.oauth2Login().userInfoEndpoint()
				.customUserType(WordpressUser.class, "wordpress");
	}
}
