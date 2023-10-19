package ca.uhn.fhir.jpa.starter.custom.event;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
public class FailureEvents {

	private static final Logger ourLog = LoggerFactory.getLogger(FailureEvents.class);

	@EventListener
	public void onFailure(AuthenticationFailureBadCredentialsEvent badCredentials) {
		if (badCredentials.getAuthentication() instanceof BearerTokenAuthenticationToken) {
			// ... handle
		}
		ourLog.info("onFailure");

		// ourLog.info(badCredentials.getClass().getName());
		// ourLog.info(badCredentials.toString());
		// ourLog.info(badCredentials.getAuthentication().toString());
		ourLog.info(badCredentials.getException().getLocalizedMessage());
	}
}