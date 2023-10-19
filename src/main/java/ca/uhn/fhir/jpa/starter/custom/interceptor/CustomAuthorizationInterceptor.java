package ca.uhn.fhir.jpa.starter.custom.interceptor;

import java.util.Collection;
import java.util.List;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.InternalErrorException;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRuleBuilder;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;

@Component
public class CustomAuthorizationInterceptor extends AuthorizationInterceptor {

	private static final org.slf4j.Logger ourLog = org.slf4j.LoggerFactory
			.getLogger(CustomAuthorizationInterceptor.class);

	
	@Override
	public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {
		IAuthRuleBuilder authRuleBuilder = new RuleBuilder();

		try {
			// Access the currently authenticated user's details
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

			if (authentication instanceof AnonymousAuthenticationToken) {
				if (theRequestDetails.getParameters().containsKey("identifier")) {
					ourLog.info("called");
					return authRuleBuilder.allow().read().resourcesOfType("Organization").withAnyId().build();
				} else {
					return authRuleBuilder.allow().metadata().build();
				}
			}

			/// can be [JwtAuthenticationToken] or [OAuth2AuthenticationToken]
			if (authentication != null && authentication.isAuthenticated()) {

				if (authentication instanceof JwtAuthenticationToken) {
					ourLog.info(
							"PARTITION = " + ((JwtAuthenticationToken) authentication).getTokenAttributes().get("partition"));
				} else if (authentication instanceof OAuth2AuthenticationToken) {
					ourLog.info(
							"PARTITION = "
									+ ((OAuth2AuthenticationToken) authentication).getPrincipal().getAttribute("partition"));
				}

				ourLog.info("authentication if type of" + authentication.toString());

				// Log user roles
				Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
				authorities.forEach(authority -> {
					ourLog.info("authorities: " + authority.getAuthority());
				});
				ourLog.info("credential: " + authentication.getCredentials());
				ourLog.info("principal: " + authentication.getPrincipal().toString());

				return authRuleBuilder.allowAll().build();
			}
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage());
		}

		return authRuleBuilder.allow().metadata().build();
	}
}
