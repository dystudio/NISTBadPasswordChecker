# NIST Bad Password Checker
A Keycloak Password Policy Provider implementing checks against the [NIST Special Publication 800-63-3: Digital Authentication Guidelines](https://pages.nist.gov/800-63-3/). The checks are performed using the web API provided by [NIST Bad Password Checker API](https://nist.badpasswordcheck.com/).

## Installation
The NIST Bad Password Checker is installed by copying the `NISTBadPasswordChecker.jar` file into the `{KEYCLOAK_HOME}\standalone\deployments\` folder. Further configuration depends on whether a globale API key is used for all realms, or if each realm is required to provide an API key when the NIST Bad Password Checker is enabled in the `Authentication: Password Policy`.
 
In either case, one or more API keys will need to be provided. If an API key for the NIST Bad Password Checker API has not already been obtained, head on over to [NIST Bad Password Checker API](https://nist.badpasswordcheck.com/) and get one.

#### Global API Key
If using the NIST Bad Password Checker as a global provider, there are several ways to provide the API key to the Keycloak service.

- the value of the System property `nist.password.checker.key`
- the value of the System environment variable `nist.password.checker.key`
- the value of the SPI config property: `apiKey`

Note that the preferred way for global configuration is to set the `nist.password.checker.key` via a system property or environment variable.

To configure the NIST Password Checker global API Key via the SPI configuration, run the following jboss-cli script:
```
/subsystem=keycloak-server/spi=password-policy:add()
/subsystem=keycloak-server/spi=password-policy/provider=nistBadPasswordChecker:add(enabled=true)
/subsystem=keycloak-server/spi=password-policy/provider=nistBadPasswordChecker:write-attribute(name=properties.apiKey, value={website_provided_api_key})
:reload
```
**NOTE:** Substitute `{website_provided_api_key}` in the script with the API key provided by the NIST Bad Password Checker API web site.

#### Realm Specific API Key
If a global API key is not configured, each Realm is required to provide an API key when the NIST Bad Password Checker password policy is added. Be aware that API keys **can** be shared across Realms.

### How to use
Once the NIST Bad Password Checker has been deployed and Keycloak has been restarted, log into Keycloak and select the Realm to apply the password policy to. Navigate to the `Authorization: Password Policy` tab and select the `NIST Bad Password Checker` from the list of available policies.

If the NIST Bad Password Checker has been deployed to use a global API key, no further configuration is required. However, if the NIST Bad Password Checker has been deployed without a global API key, then paste the API key provided by the NIST Bad Password Checker API web site into the text box.

Finally, click the `Save` button to save the password policy with the NIST Bad Password Checker enabled.

## Disclaimer
This plugin was developed from scratch to mitigate the need to maintain local password blacklist files in the current threat landscape. With the prolific occurrences of password breaches, new password blacklists would need to be deployed on a regular basis. The NIST Bad Password Checker API mitigates this need by maintaining an updated list of password blacklists composed from several resources.

This product is licensed under the GNU General Public License 3.0.

## References
1. [Keycloak](https://www.keycloak.org/)
2. [Implementing new password policy](https://lists.jboss.org/pipermail/keycloak-user/2017-February/009425.html)
3. [Implementing an SPI](https://www.keycloak.org/docs/latest/server_development/index.html#_providers) 
4. [NIST Special Publication 800-63-3: Digital Authentication Guidelines](https://pages.nist.gov/800-63-3/)
5. [NIST Bad Password Checker API](https://nist.badpasswordcheck.com/)
