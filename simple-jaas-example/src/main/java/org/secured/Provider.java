/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2015-2018 Oracle and/or its affiliates. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License.  You can
 * obtain a copy of the License at
 * https://oss.oracle.com/licenses/CDDL+GPL-1.1
 * or LICENSE.txt.  See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at LICENSE.txt.
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

package org.secured;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Provider implements LoginModule {

    private static final Logger LOGGER = Logger.getLogger(Provider.class.getName());

    private Subject subject;
    private CallbackHandler callbackHandler;

    // not used in this simple LoginModule but can be useful when LoginModule are stacked
    private Map<String, ?> sharedState;
    private Map<String, ?> options;

    protected List<UserPrincipal> userPrincipals;
    protected List<RolePrincipal> rolePrincipals;

    @Override
    public void initialize(final Subject subject, final CallbackHandler callbackHandler, final Map<String, ?> sharedState, final Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;

        this.userPrincipals = new ArrayList<>();
        this.rolePrincipals = new ArrayList<>();

        // for demo purpose
        System.out.println("=== Options ===");
        options.entrySet().stream()
                .forEach(System.out::println);

        System.out.println("=== Shared state ===");
        sharedState.entrySet().stream()
                .forEach(System.out::println);
    }

    @Override
    public boolean login() throws LoginException {
        final Callback[] callbacks = new Callback[] {
            new NameCallback("username"),
            new PasswordCallback("password", false)
        };
        try {
            callbackHandler.handle(callbacks);

        } catch (IOException | UnsupportedCallbackException e) {
            LOGGER.log(Level.SEVERE, "Can not authenticate user.", e);
            return false;
        }

        final String username = NameCallback.class.cast(callbacks[0]).getName();
        final char[] password = PasswordCallback.class.cast(callbacks[1]).getPassword();

        if (!"snoopy".equals(username) || !"woodst0ck".equals(new String(password))) {
            return false;
        }

        userPrincipals.add(new UserPrincipal("snoopy"));
        return true;
    }

    @Override
    public boolean commit() throws LoginException {
        // grab the roles
        rolePrincipals.add(new RolePrincipal("RedBaron"));
        rolePrincipals.add(new RolePrincipal("JoeCool"));
        rolePrincipals.add(new RolePrincipal("MansBestFriend"));

        this.subject.getPrincipals().addAll(userPrincipals);
        this.subject.getPrincipals().addAll(rolePrincipals);

        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        clear();
        return true;
    }

    private void clear() {
        if (rolePrincipals != null) {
            rolePrincipals.clear();
            rolePrincipals = null;
        }

        if (userPrincipals != null) {
            userPrincipals.clear();
            userPrincipals = null;
        }
    }

    @Override
    public boolean logout() throws LoginException {
        clear();
        return true;
    }
}
