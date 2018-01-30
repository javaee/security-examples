/*
 * Copyright (c) 2015-2018 Oracle and/or its affiliates. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Oracle nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
