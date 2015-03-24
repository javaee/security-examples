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
