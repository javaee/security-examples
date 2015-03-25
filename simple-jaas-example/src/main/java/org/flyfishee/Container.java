package org.flyfishee;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import java.security.Principal;
import java.util.HashMap;

public class Container {

    public static void main(String[] args) throws Exception {

        // 1. the definition of the credentials
        final CallbackHandler callbackHandler = callbacks -> {
            for (final Callback callback : callbacks) {
                if (callback instanceof NameCallback) {
                    ((NameCallback) callback).setName("snoopy");

                } else if (callback instanceof PasswordCallback) {
                    ((PasswordCallback) callback).setPassword("woodst0ck".toCharArray());

                } else {
                    throw new UnsupportedCallbackException(callback);
                }
            }
        };

        // 2. the configuration
        final Configuration config = new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {

                return new AppConfigurationEntry[]{
                    new AppConfigurationEntry(
                        "org.secured.Provider",
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                        new HashMap<String, Object>() {
                            {
                                put("ldapUrl", "ldap://yourserverhere:389");
                                put("userFilter", "(uid={user})");
                                put("baseDN", "ou=people,o=acme");
                                put("bindDn", "cn=Username,ou=people,o=organization");
                            }
                        }
                    )
                };
            }
        };

        // if the config is not provided then, it looks for the system property java.security.auth.login.config
        // and loads the configuration from the file
        // System.setProperty("java.security.auth.login.config", Thread.currentThread().getContextClassLoader().getResource("jaas.config").toExternalForm());
        // final LoginContext loginContext = new LoginContext("example", new Subject(), callbackHandler);

        // 3. the API usage
        final LoginContext loginContext = new LoginContext("example", new Subject(), callbackHandler, config);

        // this will properly instantiate the login module and authenticate the user
        loginContext.login();

        // at the end of the authentication, the subject should contain the principals
        final Subject subject = loginContext.getSubject();

        // UserName Principal should be snoopy
        // Role Principals should be
        // - RedBaron
        // - JoeCool
        // - MansBestFriend

        System.out.println("=== User principals ===");
        for (final Principal principal : subject.getPrincipals()) {
            System.out.println(principal);
        }

    }
}
