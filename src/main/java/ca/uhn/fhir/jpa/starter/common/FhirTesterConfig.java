package ca.uhn.fhir.jpa.starter.common;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.interceptor.api.Hook;
import ca.uhn.fhir.interceptor.api.Pointcut;
import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.interceptor.model.RequestPartitionId;
import ca.uhn.fhir.jpa.starter.AppProperties;
import ca.uhn.fhir.rest.client.api.IGenericClient;
import ca.uhn.fhir.rest.client.interceptor.CookieInterceptor;
import ca.uhn.fhir.rest.server.util.ITestingUiClientFactory;
import ca.uhn.fhir.to.FhirTesterMvcConfig;
import ca.uhn.fhir.to.TesterConfig;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

// @formatter:off
/**
 * This spring config file configures the web testing module. It serves two
 * purposes:
 * 1. It imports FhirTesterMvcConfig, which is the spring config for the
 *    tester itself
 * 2. It tells the tester which server(s) to talk to, via the testerConfig()
 *    method below
 */
@Configuration
@Import(FhirTesterMvcConfig.class)
@Conditional(FhirTesterConfigCondition.class)
public class FhirTesterConfig {

	/**
	 * This bean tells the testing webpage which servers it should configure itself
	 * to communicate with. In this example we configure it to talk to the local
	 * server, as well as one public server. If you are creating a project to
	 * deploy somewhere else, you might choose to only put your own server's
	 * address here.
	 * <p>
	 * Note the use of the ${serverBase} variable below. This will be replaced with
	 * the base URL as reported by the server itself. Often for a simple Tomcat
	 * (or other container) installation, this will end up being something
	 * like "http://localhost:8080/hapi-fhir-jpaserver-starter". If you are
	 * deploying your server to a place with a fully qualified domain name,
	 * you might want to use that instead of using the variable.
	 */
  @Bean
  public TesterConfig testerConfig(AppProperties appProperties) {
    TesterConfig retVal = new TesterConfig();
    appProperties.getTester().forEach((key, value) -> {
	     	retVal
			 .addServer()
			 .withId(key)
			 .withFhirVersion(value.getFhir_version())
			 .withBaseUrl(value.getServer_address())
			 .withName(value.getName());
			retVal.setRefuseToFetchThirdPartyUrls(
			 value.getRefuse_to_fetch_third_party_urls());
			retVal.setClientFactory(new AddCookiesClientFactory());
	 });
    return retVal;
  }
}

final class AddCookiesClientFactory implements ITestingUiClientFactory {
   public AddCookiesClientFactory() {
   }

   public IGenericClient newClient(FhirContext theFhirContext, HttpServletRequest theRequest, String theServerBaseUrl) {
      IGenericClient client = theFhirContext.newRestfulGenericClient(theServerBaseUrl);
		Cookie[] cookies = theRequest.getCookies();
		for (Cookie cookie : cookies) {
			client.registerInterceptor( new CookieInterceptor(cookie.getName()+"="+cookie.getValue()));
		}

      return client;
   }
}
@Interceptor
final class PartitionInterceptorReadAllPartitions {

   @Hook(Pointcut.STORAGE_PARTITION_IDENTIFY_READ)
   public RequestPartitionId readPartition() {
      return RequestPartitionId.allPartitions();
   }
}
