package ca.uhn.fhir.jpa.starter.custom.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private static final Logger ourLog = LoggerFactory.getLogger(SecurityConfig.class);

	@Value("${spring.security.oauth2.client.provider.keycloak.jwk-set-uri}")
	private String jwkSetUri;

	@Bean(name = "JwtDecoder")
	public JwtDecoder jwtDecoder() {
		return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
	}

	@Order(1)
	@Bean
	public SecurityFilterChain clientFilterChain(HttpSecurity http) throws Exception {
		try {

			http
					.authorizeRequests(authorizeRequests -> authorizeRequests
							.antMatchers("/login", "/logout").permitAll()
							.antMatchers(HttpMethod.GET, "/fhir/Composition", "/fhir/Parameters", "/fhir/Binary").permitAll()
							.antMatchers(HttpMethod.GET, "/fhir/Organization").permitAll()
							.antMatchers("/", "/home", "/fhir/**", "/resource", "/search", "/read", "/history", "/delete",
									"/create", "/update")
							.authenticated())
					.oauth2Login().and()
					.oauth2Client().and()
					.oauth2ResourceServer((oauth2) -> oauth2
							.jwt().and()
							.accessDeniedHandler(new JsonAccessDeniedHandler())
							.authenticationEntryPoint(new JsonAuthenticationEntryPoint()))
					.cors().and()
					.exceptionHandling(exceptionHandling -> exceptionHandling
							.defaultAuthenticationEntryPointFor(
									new JsonAuthenticationEntryPoint(),
									req -> req.getRequestURI().startsWith("/fhir/"))
							.defaultAccessDeniedHandlerFor(
									new JsonAccessDeniedHandler(),
									req -> req.getRequestURI().startsWith("/fhir/")))
					.csrf(csrf -> csrf.ignoringAntMatchers("/fhir/**"))
					.logout(logout -> logout.permitAll());

			// http.oauth2Login().and()
			// .oauth2Client();
			// http.oauth2ResourceServer((oauth2) ->
			// oauth2.jwt().and().accessDeniedHandler(new JsonAccessDeniedHandler()));

			// http
			// .cors();
			// http
			// .authorizeRequests()
			// .antMatchers("/login", "/logout")
			// .permitAll()
			// .antMatchers(HttpMethod.GET, "/fhir/Composition", "/fhir/Parameters",
			// "/fhir/Binary")
			// .permitAll()
			// .antMatchers("/", "/home", "/fhir/**", "/resource", "/search", "/read",
			// "/history", "/delete", "/create",
			// "/update")
			// .authenticated()
			// .and()
			// .exceptionHandling(
			// exceptionHandling -> exceptionHandling
			// .defaultAuthenticationEntryPointFor(
			// new JsonAuthenticationEntryPoint(),
			// req -> req.getRequestURI().startsWith("/fhir/"))
			// .defaultAccessDeniedHandlerFor(
			// new JsonAccessDeniedHandler(),
			// req -> req.getRequestURI().startsWith("/fhir/")));
			// http
			// .csrf()
			// .ignoringAntMatchers("/fhir/**");
			// http
			// .logout()
			// .permitAll();
		} catch (Exception e) {
			ourLog.error("catch exception on clientFilterChain : ", e);
		}
		return http.build();
	}

	@Order(2)
	@Bean
	public SecurityFilterChain resourceServerFilterChain(HttpSecurity http) throws Exception {
		http
				.authorizeRequests()
				.mvcMatchers("/js/**").permitAll()
				.mvcMatchers("/css/**").permitAll()
				.mvcMatchers("/images/**").permitAll()
				.mvcMatchers("/html/**").permitAll()
				.antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
				.antMatchers("/fhir/metadata").permitAll();

		return http.build();

	}

	public class JsonAuthenticationEntryPoint implements AuthenticationEntryPoint {

		@Override
		public void commence(HttpServletRequest request, HttpServletResponse response,
				AuthenticationException exception) throws IOException {
			ourLog.info("JsonAuthenticationEntryPoint");
			ourLog.info(exception.toString());
			response.setStatus(HttpStatus.FORBIDDEN.value());
			response.setContentType("application/json");

			String error = "Unauthorized";
			if (exception instanceof InvalidBearerTokenException && exception.getMessage().contains("Jwt expired at")) {
				error = "Jwt expired";
			}

			// Create a JSON object with the desired structure
			String jsonResponse = "{\"error\": \""
					+ error
					+ "\", \"message\": \""
					+ exception.getLocalizedMessage()
					+ "\"}";

			response.getWriter().write(jsonResponse);

		}
	}

	public class JsonAccessDeniedHandler implements AccessDeniedHandler {

		@Override
		public void handle(HttpServletRequest request, HttpServletResponse response,
				AccessDeniedException exception) throws IOException, ServletException {
			ourLog.info("JsonAccessDeniedHandler");

			ourLog.info(request.toString());
			ourLog.info(exception.toString());

			response.setStatus(HttpStatus.FORBIDDEN.value());
			response.setContentType("application/json");

			String error = "Unauthorized";

			// Create a JSON object with the desired structure
			String jsonResponse = "{\"error\": \""
					+ error
					+ "\", \"message\": \""
					+ exception.getLocalizedMessage()
					+ "\"}";

			response.getWriter().write(jsonResponse);
		}

	}

}
