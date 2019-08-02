/*
 * Copyright 2019 Top Cat Technology Solutions, LLC and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *  
 *  This file is part of NISTBadPasswordChecker.
 *
 *  NISTBadPasswordChecker is free software: you can redistribute it and/or 
 *  modify it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or any later
 *  version.
 *  
 *  NISTBadPasswordChecker is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
 *  Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License along
 *  with NISTBadPasswordChecker.  If not, see <https://www.gnu.org/licenses/>.
 */

package tech.topcat.keycloak.pwdpol;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.policy.BlacklistPasswordPolicyProviderFactory.PasswordBlacklist;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PasswordPolicyProviderFactory;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.google.common.hash.Hashing;
import com.google.common.net.HttpHeaders;

/**
 * Creates {@link NISTBadPasswordPolicyProvider} instances.
 * <p>
 * The <a href="https://nist.badpasswordcheck.com/">NIST Bad Password Checker</a> is a free service used to validate the password according to <a href="https://pages.nist.gov/800-63-3/">NIST Special Publication 800-63-3: Digital Authentication Guidelines</a>.</p> 
 * <p>The NIST Bad Password Checker can be configured via the <em>Authentication: Password Policy</em> section in the admin-console.
 * An API provided by the NIST Bad Password Checker interface is required, and can be provided either globally or per realm.</p>
 * <p>If an API is provided globally, it is used for all realms which have the NIST Bad Password Checker password policy enabled.</p>
 * <p>The value of the NIST API Key is derived as follows</p>
 * <ol>
 * <li>the value of the System property {@code nist.password.checker.key}</li>
 * <li>the value of the System environment variable {@code nist.password.checker.key}</li>
 * <li>the value of the SPI config property: {@code apiKey} when explicitly configured</li>
 * </ol>
 * <p>Note that the preferred way for global configuration is to set the {@code nist.password.checker.key} System property or environment variable.</p>
 * <p>To configure the NIST Password Checker global API Key via the SPI configuration, run the following jboss-cli script:</p>
 * <pre>{@code
 * /subsystem=keycloak-server/spi=password-policy:add()
 * /subsystem=keycloak-server/spi=password-policy/provider=nistBadPasswordChecker:add(enabled=true)
 * /subsystem=keycloak-server/spi=password-policy/provider=nistBadPasswordChecker:write-attribute(name=properties.apiKey, value=website_provided_api_key)
 * }</pre>
 * <p><b>NOTE:</b>Substitute {@code website_provided_api_key} in the script with the API key provided by the NIST Bad Password Checker website.</p>
 * <p>If a global API key is not configured, each realm is required to provide an API key when the NIST Bad Password Checker password policy is added.</p>
 * <p>
 * @see <a href="https://nist.badpasswordcheck.com/">NIST Bad Password Checker</a> for details on the NIST Bad Password Checker web api.
 * @see <a href="https://pages.nist.gov/800-63-3/">NIST Special Publication 800-63-3: Digital Authentication Guidelines</a> for details on the NIST Special Publication. 
 */
public class NISTBadPasswordPolicyProviderFactory implements PasswordPolicyProviderFactory {
	public static final String ID = "nistBadPasswordChecker";
	public static final String SYSTEM_PROPERTY = "nist.password.checker.key";
    public static final String SPI_PROPERTY = "apiKey";

	private static final Logger LOG = Logger.getLogger(NISTBadPasswordPolicyProviderFactory.class);
	private static final String NIST_URL = "https://api.badpasswordcheck.com/check/%s";
	
	private Scope config;
	private volatile String globalNistApiKey;
	
	@Override
	public void close() {
	}

	@Override
	public PasswordPolicyProvider create(KeycloakSession session) {
		LOG.debug("create() method called");
		checkGlobalApiKey();
		return new NISTBadPasswordPolicyProvider(session, this);
	}

	@Override
	public String getId() {
		return ID;
	}

	@Override
	public void init(Scope config) {
		LOG.debug("init() method called");
		this.config = config;
		
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	public String getConfigType() {
		LOG.debug("getConfigType() method called");
		checkGlobalApiKey();
		return globalNistApiKey == null ? PasswordPolicyProvider.STRING_CONFIG_TYPE : null;
	}

	@Override
	public String getDefaultConfigValue() {
		LOG.debug("getDefaultConfigValue() method called");
		return globalNistApiKey == null ? "" : null;
	}

	@Override
	public String getDisplayName() {
		return "NIST Bad Password Checker";
	}

	@Override
	public boolean isMultiplSupported() {
		return false;
	}
	
	/**
	 * Builds an instance of the {@code NISTBadPasswordChecker} object.
	 * @param apiKey - the API key provided by the user, if allowed. If a global API key is used, that key is stored in the instance.
	 * @param session - The {@code KeycloakSession} object for the password being tested.
	 * @return an instance of the {@code NISTBadPasswordChecker} object.
	 */
	public NISTBadPasswordChecker buildNISTBadPasswordChecker(String apiKey, KeycloakSession session) {
		LOG.debugf("buildNISTBadPasswordChecker() method called with key: [%s]", apiKey);
		if (apiKey == null || apiKey.equalsIgnoreCase("undefined")) {
			checkGlobalApiKey();
			apiKey = globalNistApiKey;
		}
		return new NISTBadPasswordChecker(apiKey, session);
	}
	
	/**
	 * Does the heavy lifting of calling the NIST Bad Password Checker web API
	 * to validate the provided password can be used.
	 */
	public static class NISTBadPasswordChecker implements PasswordBlacklist {
		private static final Logger LOG = Logger.getLogger(NISTBadPasswordChecker.class);
		private final String name;
		private final KeycloakSession session;
		
		public NISTBadPasswordChecker(String name, KeycloakSession session) {
			LOG.debugf("constructor called with name: [%s]", name);
			if (name == null) {
				throw new IllegalStateException("NIST Password Checker API Key was not provided.");
			}

			this.name = name;
			LOG.debugf("NIST api key: [%s]", name);
			this.session = session;
		}

		@SuppressWarnings("unchecked")
		@Override
		public boolean contains(String password) {
			LOG.debugf("isBadPassword() method called with parameters: [%s]", password);
			boolean result = false;
			
			// Okay to use per Google documentation because:
			// a) the NIST Bad Password Checker API requires SHA-1 hashes and
			// b) we aren't using the hash to store the password,
			@SuppressWarnings("deprecation")
			String sha1hex = Hashing.sha1()
					  .hashString(password, StandardCharsets.UTF_8)
					  .toString();
			LOG.debugf("SHA 1 value is: [%s]", sha1hex);
			
			HttpClientProvider httpClientProvider = session.getProvider(HttpClientProvider.class);
			if (httpClientProvider == null) {
				throw new IllegalStateException("No http client object available");
			}
			
			HttpClient client = httpClientProvider.getHttpClient();
			HttpUriRequest request = RequestBuilder.get().setUri(String.format(NIST_URL, sha1hex)).setHeader(HttpHeaders.AUTHORIZATION, name).build();
			try {
				HttpResponse response = client.execute(request);
				if (response.getStatusLine().getStatusCode() == 200) {
					ObjectMapper mapper = new ObjectMapper();
					Map<String, Boolean> nistResultMap = null;
					try (BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()))) {
						nistResultMap = mapper.readValue(reader, Map.class);
						result = nistResultMap.getOrDefault("found", false);
					}
				} else {
					LOG.warnf("NIST Bad Password Check response: [%s]", response.getStatusLine());
				}
			} catch (IOException e) {
				LOG.error(e);
			}
						
			LOG.debugf("NIST password check response: %s", result);
			return result;
		}

		@Override
		public String getName() {
			return name;
		}
		
	}

	/*
	 * Checks for the global API key. If the key is found, individual realms 
	 * are prevented from providing their own key.
	 */
	private void checkGlobalApiKey() {
		LOG.debug("checkGlobalApiKey() method called"); 
		if (globalNistApiKey == null) {
			synchronized (this) {
                if (globalNistApiKey == null) {
                    globalNistApiKey = System.getProperty(SYSTEM_PROPERTY);
                    if (globalNistApiKey == null) {
                    	globalNistApiKey = System.getenv(SYSTEM_PROPERTY);
                    	if (globalNistApiKey == null) {
                    		globalNistApiKey = config.get(SPI_PROPERTY);
                    	}
                    }
                }
        		LOG.debugf("NIST global api key: [%s]", globalNistApiKey);
            }			
		}
	}
}
