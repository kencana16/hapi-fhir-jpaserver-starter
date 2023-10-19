// Source code is decompiled from a .class file using FernFlower decompiler.
package ca.uhn.fhir.jpa.starter.custom.config;

import ca.uhn.fhir.i18n.HapiLocalizer;
import ca.uhn.fhir.i18n.Msg;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.api.server.SystemRequestDetails;
import ca.uhn.fhir.rest.server.RestfulServer;
import ca.uhn.fhir.rest.server.exceptions.InvalidRequestException;
import ca.uhn.fhir.rest.server.tenant.ITenantIdentificationStrategy;
import ca.uhn.fhir.util.UrlPathTokenizer;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public class TokenBaseTenantIdentificationStrategy implements ITenantIdentificationStrategy {
	private static final Logger ourLog = LoggerFactory.getLogger(TokenBaseTenantIdentificationStrategy.class);

	public TokenBaseTenantIdentificationStrategy() {
	}

	public void extractTenant(UrlPathTokenizer theUrlPathTokenizer, RequestDetails theRequestDetails) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String tenantId = null;

		boolean isSystemRequest = theRequestDetails instanceof SystemRequestDetails;
		String firstPath = (String) StringUtils.defaultIfBlank(theUrlPathTokenizer.peek(), (CharSequence) null);
		if (isSystemRequest || firstPath.startsWith("$")) {
			tenantId = "DEFAULT";
			theRequestDetails.setTenantId(tenantId);
			ourLog.trace("No tenant ID found for system request; using DEFAULT.");
		}

		if (authentication instanceof JwtAuthenticationToken) {
			tenantId = (String) ((JwtAuthenticationToken) authentication).getTokenAttributes().get("partition");

			theRequestDetails.setTenantId(tenantId);
		} else if (authentication instanceof OAuth2AuthenticationToken) {
			tenantId = (String) ((OAuth2AuthenticationToken) authentication).getPrincipal().getAttribute("partition");

			theRequestDetails.setTenantId(tenantId);
		}

		ourLog.info("tenant id used => " + tenantId);
		if (tenantId == null || tenantId == "null" || StringUtils.isBlank(tenantId)) {
			HapiLocalizer localizer = theRequestDetails.getServer().getFhirContext().getLocalizer();
			String var10002 = Msg.code(307);
			throw new InvalidRequestException(
					var10002 + localizer.getMessage(RestfulServer.class, "rootRequest.multitenant", new Object[0]));
		}
	}

	public String massageServerBaseUrl(String theFhirServerBase, RequestDetails theRequestDetails) {
		String result = theFhirServerBase;

		return result;
	}
}
