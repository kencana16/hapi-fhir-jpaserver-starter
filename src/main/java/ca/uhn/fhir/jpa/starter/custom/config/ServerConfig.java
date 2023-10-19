package ca.uhn.fhir.jpa.starter.custom.config;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;

import ca.uhn.fhir.jpa.model.config.PartitionSettings;
import ca.uhn.fhir.jpa.starter.custom.interceptor.CustomAuthorizationInterceptor;
import ca.uhn.fhir.rest.server.RestfulServer;
import ca.uhn.fhir.rest.server.interceptor.partition.RequestTenantPartitionInterceptor;
import ca.uhn.fhir.rest.server.tenant.UrlBaseTenantIdentificationStrategy;

@Configuration
public class ServerConfig {
	@Autowired
	PartitionSettings partitionSettings;

	@Autowired
	RestfulServer resfullServer;

	@PostConstruct
	private void initPartitionSetting() {
		// Enable partition
		partitionSettings.setPartitioningEnabled(true);

		// Set the tenant identification strategy
		// DEFAULT : resfullServer.setTenantIdentificationStrategy(new
		// UrlBaseTenantIdentificationStrategy());
		resfullServer.setTenantIdentificationStrategy(new TokenBaseTenantIdentificationStrategy());

		// Use the tenant ID supplied by the tenant identification strategy
		// to serve as the partitioning ID
		resfullServer.registerInterceptor(new RequestTenantPartitionInterceptor());

		resfullServer.registerInterceptor(new CustomAuthorizationInterceptor());

	}
}
