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
import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;

public class Container {

    public static void main(String[] args) throws Exception {

        final CallbackHandler callbackHandler = new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                final NameCallback username = (NameCallback) callbacks[0];
                final PasswordCallback password = (PasswordCallback) callbacks[1];

                username.setName("snoopy");
                password.setPassword("woodst0ck".toCharArray());
            }
        };

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

        final LoginContext loginContext = new LoginContext("example", new Subject(), callbackHandler, config);

        loginContext.login();

        final Subject subject = loginContext.getSubject();


        // TODO
        // UserName Principal should be snoopy
        // Role Principals should be
        // - RedBaron
        // - JoeCool
        // - MansBestFriend

        for (final Principal principal : subject.getPrincipals()) {
            System.out.println(principal);
        }

    }
}
