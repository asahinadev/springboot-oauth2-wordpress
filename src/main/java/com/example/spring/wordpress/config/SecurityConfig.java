package com.example.spring.wordpress.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import com.example.spring.wordpress.oauth2.user.WordpressUser;

@Configuration
@EnableWebSecurity
public class SecurityConfig
		extends WebSecurityConfigurerAdapter {

	@Override
	public void configure(WebSecurity web)
			throws Exception {
		super.configure(web);

		web.ignoring().antMatchers(
				// webjars
				"/webjars/**",
				// CSS ファイル
				"/css/**",
				// JavaScriptファイル
				"/js/**",
				// 画像ファイル
				"/img/**",
				// サウンドファイル
				"/sound/**",
				// WEB フォント
				"/font/**",
				"/fonts/**",
				// 外部ライブラリ
				"/exlib/**"
		/**/
		);
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		super.configure(auth);
	}

	@Override
	protected void configure(HttpSecurity http)
			throws Exception {
		super.configure(http);

		http.formLogin().disable();
		http.logout().disable();

		http.httpBasic().disable();

		http.csrf().disable();

		http.oauth2Login()

				// 認証エンドポイント
				.authorizationEndpoint()
				.and()

				// リダイレクトエンドポイント
				.redirectionEndpoint()
				.and()

				// アクセストークンエンドポイント
				.tokenEndpoint()
				.and()

				// ユーザー情報エンドポイント
				.userInfoEndpoint()
				.customUserType(WordpressUser.class, "wordpress")
				.and();

	}
}
