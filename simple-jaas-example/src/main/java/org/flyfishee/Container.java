/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2015, 2016 Oracle and/or its affiliates. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License.  You can
 * obtain a copy of the License at
 * http://glassfish.dev.java.net/public/CDDL+GPL_1_1.html
 * or packager/legal/LICENSE.txt.  See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at packager/legal/LICENSE.txt.
 *
 * GPL Classpath Exception:
 * Oracle designates this particular file as subject to the "Classpath"
 * exception as provided by Oracle in the GPL Version 2 section of the License
 * file that accompanied this code.
 *
 * Modifications:
 * If applicable, add the following below the License Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyright [year] [name of copyright owner]"
 *
 * Contributor(s):
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding "[Contributor]
 * elects to include this software in this distribution under the [CDDL or GPL
 * Version 2] license."  If you don't indicate a single choice of license, a
 * recipient has the option to distribute your version of this file under
 * either the CDDL, the GPL Version 2 or to extend the choice of license to
 * its licensees as provided above.  However, if you add GPL Version 2 code
 * and therefore, elected the GPL Version 2 license, then the option applies
 * only if the new code is made subject to such option by the copyright
 * holder.
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
