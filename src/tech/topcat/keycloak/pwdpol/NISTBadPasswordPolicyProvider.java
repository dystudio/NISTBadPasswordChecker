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

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.BlacklistPasswordPolicyProvider;
import org.keycloak.policy.BlacklistPasswordPolicyProviderFactory.PasswordBlacklist;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PolicyError;

import tech.topcat.keycloak.pwdpol.NISTBadPasswordPolicyProviderFactory.NISTBadPasswordChecker;

public class NISTBadPasswordPolicyProvider implements PasswordPolicyProvider {
	
	private static final Logger LOG = Logger.getLogger(NISTBadPasswordPolicyProvider.class);
	private KeycloakSession session;
	private NISTBadPasswordPolicyProviderFactory factory;
	
	public NISTBadPasswordPolicyProvider(KeycloakSession session, NISTBadPasswordPolicyProviderFactory factory) {
		this.session = session;
		this.factory = factory;
	}
	
	@Override
	public void close() {
	}

	@Override
	public Object parseConfig(String value) {
		LOG.debugf("parseConfig() method called with parameter: [%s]", value);
		return factory.buildNISTBadPasswordChecker(value, session);
	}

	@Override
	public PolicyError validate(String username, String password) {
		LOG.debugf("validate() method called with parameters: [%s] [%s]", username, password);
		return validate(session.getContext().getRealm(), null, password);
	}

	@Override
	public PolicyError validate(RealmModel realm, UserModel user, String password) {
		LOG.debugf("validate(RealmModel, UserModel, String) called with parameters: [%s] [%s] [%s]", realm.getName(), user.getUsername(), password);
		Object policyConfig = realm.getPasswordPolicy().getPolicyConfig(NISTBadPasswordPolicyProviderFactory.ID);
		if (policyConfig == null) {
			LOG.debug("Policy config is null");
			return null;
		}
		
		LOG.debugf("Policy config class is: [%s]", policyConfig.getClass().getTypeName());
		if (!(policyConfig instanceof PasswordBlacklist)) {
			LOG.debug("Policy config is not an instance of PasswordBlacklist");
			return null;
		}
		
		PasswordBlacklist passwordChecker = (NISTBadPasswordChecker) policyConfig;
		
		if (!passwordChecker.contains(password)) {
			return null;
		}
		
		return new PolicyError(BlacklistPasswordPolicyProvider.ERROR_MESSAGE);
	}

}
