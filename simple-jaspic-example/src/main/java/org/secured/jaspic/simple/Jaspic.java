/*
 * Copyright 2013 OmniFaces.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.secured.jaspic.simple;

import javax.faces.context.FacesContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

import static java.lang.Boolean.TRUE;
import static javax.security.auth.message.AuthStatus.SUCCESS;
import static org.secured.jaspic.simple.Utils.isEmpty;
import static org.secured.jaspic.simple.Utils.isOneOf;


/**
 * A set of utility methods for using the JASPIC API, specially in combination with
 * the OmniServerAuthModule.
 * <p>
 * Note that this contains various methods that assume being called from a JSF context.
 *
 * @author Arjan Tijms
 *
 */
public final class Jaspic {

    public static final String IS_AUTHENTICATION = "org.omnifaces.security.message.request.authentication";
    public static final String IS_AUTHENTICATION_FROM_FILTER = "org.omnifaces.security.message.request.authenticationFromFilter";
    public static final String IS_SECURE_RESPONSE = "org.omnifaces.security.message.request.secureResponse";
    public static final String IS_REFRESH = "org.omnifaces.security.message.request.isRefresh";
    public static final String DID_AUTHENTICATION = "org.omnifaces.security.message.request.didAuthentication";

    public static final String AUTH_PARAMS = "org.omnifaces.security.message.request.authParams";

    public static final String LOGGEDIN_USERNAME = "org.omnifaces.security.message.loggedin.username";
    public static final String LOGGEDIN_ROLES = "org.omnifaces.security.message.loggedin.roles";
    public static final String LAST_AUTH_STATUS = "org.omnifaces.security.message.authStatus";

    public static final String CONTEXT_REGISTRATION_ID = "org.omnifaces.security.message.registrationId";

    // Key in the MessageInfo Map that when present AND set to true indicated a protected resource is being accessed.
    // When the resource is not protected, GlassFish omits the key altogether. WebSphere does insert the key and sets
    // it to false.
    private static final String IS_MANDATORY = "javax.security.auth.message.MessagePolicy.isMandatory";
    private static final String REGISTER_SESSION = "javax.servlet.http.registerSession";

    private Jaspic() {
    }

    public static boolean authenticate(HttpServletRequest request, HttpServletResponse response, AuthParameters authParameters) {
        try {
            request.setAttribute(IS_AUTHENTICATION, true);
            if (authParameters != null) {
                request.setAttribute(AUTH_PARAMS, authParameters);
            }
            return request.authenticate(response);
        } catch (ServletException | IOException e) {
            throw new IllegalArgumentException(e);
        } finally {
            request.removeAttribute(IS_AUTHENTICATION);
            if (authParameters != null) {
                request.removeAttribute(AUTH_PARAMS);
            }
        }
    }

    public static boolean authenticateFromFilter(HttpServletRequest request, HttpServletResponse response) {
        try {
            request.setAttribute(IS_AUTHENTICATION_FROM_FILTER, true);
            return request.authenticate(response);
        } catch (ServletException e) {
            // Really problematic case, some servers (particularly JBoss Undertow since 1.1.0) throw a
            // ServletException when there's isn't actually an error, but just to indicate "nothing" has happened.
            return false;
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        } finally {
            request.removeAttribute(IS_AUTHENTICATION_FROM_FILTER);
        }
    }

    public static boolean refreshAuthentication(HttpServletRequest request, HttpServletResponse response, AuthParameters authParameters) {
        try {
            request.setAttribute(IS_REFRESH, true);
            // Doing an explicit logout is actually not really nice, as it has some side-effects that we need to counter
            // (like a SAM supporting remember-me clearing its remember-me cookie, etc). But there doesn't seem to be another
            // way in JASPIC
            request.logout();
            return authenticate(request, response, authParameters);
        } catch (ServletException e) {
            throw new IllegalArgumentException(e);
        } finally {
            request.removeAttribute(IS_REFRESH);
        }
    }

    public static AuthParameters getAuthParameters(HttpServletRequest request) {
        AuthParameters authParameters = (AuthParameters) request.getAttribute(AUTH_PARAMS);
        if (authParameters == null) {
            authParameters = new AuthParameters();
        }

        return authParameters;
    }

    public static void logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            request.logout();
            // Need to invalidate the session to really logout - request.logout only logs the user out for the *current request*
            // This is nearly always unwanted. Although the SAM's cleanSubject method can clear any session data too if needed,
            // invalidating the session is pretty much the safest way.
            request.getSession().invalidate();
        } catch (ServletException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static AuthResult validateRequest(ServerAuthModule serverAuthModule, MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) {

        AuthResult authResult = new AuthResult();

        try {
            AuthStatus status = serverAuthModule.validateRequest(messageInfo, clientSubject, serviceSubject);

            // TODO: not 100% sure about this; need mechanism for wrappers to abort the chain and signal to "do nothing"
            // TODO: use handler for "do nothing here"?
            if (status == null) {
                status = SUCCESS;
            }

            authResult.setAuthStatus(status);
        } catch (Exception exception) {
            authResult.setException(exception);
        }

        return authResult;
    }

    public static void cleanSubject(Subject subject) {
        if (subject != null) {
            subject.getPrincipals().clear();
        }
    }

    public static boolean isRegisterSession(MessageInfo messageInfo) {
        return Boolean.valueOf((String) messageInfo.getMap().get(REGISTER_SESSION));
    }

    public static boolean isProtectedResource(MessageInfo messageInfo) {
        return Boolean.valueOf((String) messageInfo.getMap().get(IS_MANDATORY));
    }

    @SuppressWarnings("unchecked")
    public static void setRegisterSession(MessageInfo messageInfo, String username, List<String> roles) {
        messageInfo.getMap().put("javax.servlet.http.registerSession", TRUE.toString());

        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
        request.setAttribute(LOGGEDIN_USERNAME, username);
        // TODO: check for existing roles and add
        request.setAttribute(LOGGEDIN_ROLES, roles);
    }

    public static boolean isAuthenticationRequest(HttpServletRequest request) {
        return TRUE.equals(request.getAttribute(IS_AUTHENTICATION));
    }

    public static boolean isAuthenticationFromFilterRequest(HttpServletRequest request) {
        return TRUE.equals(request.getAttribute(IS_AUTHENTICATION_FROM_FILTER));
    }

    public static boolean isSecureResponseRequest(HttpServletRequest request) {
        return TRUE.equals(request.getAttribute(IS_SECURE_RESPONSE));
    }

    public static boolean isRefresh(HttpServletRequest request) {
        return TRUE.equals(request.getAttribute(IS_REFRESH));
    }


    /**
     * Returns true if authorization was explicitly called for via this class (e.g. by calling {@link Jaspic#authenticate()},
     * false if authorization was called automatically by the runtime at the start of the request or directly via e.g.
     * {@link HttpServletRequest#authenticate(HttpServletResponse)}
     *
     * @param request
     * @return true if authorization was initiated via this class, false otherwise
     */
    public static boolean isExplicitAuthCall(HttpServletRequest request) {
        return isOneOf(TRUE, request.getAttribute(IS_AUTHENTICATION),
                request.getAttribute(IS_AUTHENTICATION_FROM_FILTER),
                request.getAttribute(IS_SECURE_RESPONSE)
        );
    }

    public static void notifyContainerAboutLogin(Subject clientSubject, CallbackHandler handler, String username, List<String> roles) {

        try {
            // 1. Create a handler (kind of directive) to add the caller principal (AKA user principal =basically user name, or user id) that
            // the authenticator provides.
            //
            // This will be the name of the principal returned by e.g. HttpServletRequest#getUserPrincipal
            //
            // 2 Execute the handler right away
            //
            // This will typically eventually (NOT right away) add the provided principal in an application server specific way to the JAAS 
            // Subject.
            // (it could become entries in a hash table inside the subject, or individual principles, or nested group principles etc.)

            handler.handle(new Callback[]{new CallerPrincipalCallback(clientSubject, username)});

            if (!Utils.isEmpty(roles)) {
                // 1. Create a handler to add the groups (AKA roles) that the authenticator provides.
                //
                // This is what e.g. HttpServletRequest#isUserInRole and @RolesAllowed for
                //
                // 2. Execute the handler right away
                //
                // This will typically eventually (NOT right away) add the provided roles in an application server specific way to the JAAS 
                // Subject.
                // (it could become entries in a hash table inside the subject, or individual principles, or nested group principles etc.)

                handler.handle(new Callback[]{new GroupPrincipalCallback(clientSubject, roles.toArray(new String[roles.size()]))});
            }

        } catch (IOException | UnsupportedCallbackException e) {
            // Should not happen
            throw new IllegalStateException(e);
        }
    }

    public static void setLastStatus(HttpServletRequest request, AuthStatus status) {
        request.setAttribute(LAST_AUTH_STATUS, status);
    }

    public static AuthStatus getLastStatus(HttpServletRequest request) {
        return (AuthStatus) request.getAttribute(LAST_AUTH_STATUS);
    }

    /**
     * Should be called when the callback handler is used with the intention that an actual
     * user is going to be authenticated (as opposed to using the handler for the "do nothing" protocol
     * which uses the unauthenticated identity).
     *
     */
    public static void setDidAuthentication(HttpServletRequest request) {
        request.setAttribute(DID_AUTHENTICATION, TRUE);
    }

    /**
     * Returns true if a SAM has indicated that it intended authentication to be happening during
     * the current request.
     * Does not necessarily mean that authentication has indeed succeeded, for this
     * the actual user/caller principal should be checked as well.
     *
     */
    public static boolean isDidAuthentication(HttpServletRequest request) {
        return TRUE.equals(request.getAttribute(DID_AUTHENTICATION));
    }

    public static boolean isDidAuthenticationAndSucceeded(HttpServletRequest request) {
        return TRUE.equals(request.getAttribute(DID_AUTHENTICATION)) && request.getUserPrincipal() != null;
    }

    /**
     * Gets the app context ID from the servlet context.
     *
     * <p>
     * The app context ID is the ID that JASPIC associates with the given application.
     * In this case that given application is the web application corresponding to the
     * ServletContext.
     *
     * @param context the servlet context for which to obtain the JASPIC app context ID
     * @return the app context ID for the web application corresponding to the given context
     */
    public static String getAppContextID(ServletContext context) {
        return context.getVirtualServerName() + " " + context.getContextPath();
    }

    /**
     * Registers a server auth module as the one and only module for the application corresponding to
     * the given servlet context.
     *
     * <p>
     * This will override any other modules that have already been registered, either via proprietary
     * means or using the standard API.
     *
     * @param serverAuthModule the server auth module to be registered
     * @param servletContext the context of the app for which the module is registered
     * @return A String identifier assigned by an underlying factory corresponding to an underlying factory-factory-factory registration
     */
    public static String registerServerAuthModule(ServerAuthModule serverAuthModule, ServletContext servletContext) {

        AuthStacks stacks = new AuthStacksBuilder()
                .stack()
                .name(serverAuthModule.getClass().getSimpleName())
                .setDefault()
                .module()
                .serverAuthModule(serverAuthModule)
                .controlFlag(ControlFlag.REQUIRED)
                .add()
                .add()
                .build();

        // Register the factory-factory-factory for the SAM
        String registrationId = AuthConfigFactory.getFactory().registerConfigProvider(
                new OmniAuthConfigProvider(stacks),
                "HttpServlet", getAppContextID(servletContext), "OmniSecurity authentication config provider"
        );

        // Remember the registration ID returned by the factory, so we can unregister the JASPIC module when the web module
        // is undeployed. JASPIC being the low level API that it is won't do this automatically.
        servletContext.setAttribute(CONTEXT_REGISTRATION_ID, registrationId);

        return registrationId;
    }

    /**
     * Deregisters the server auth module (and encompassing wrappers/factories) that was previously registered via a call
     * to registerServerAuthModule.
     *
     * @param servletContext the context of the app for which the module is deregistered
     */
    public static void deregisterServerAuthModule(ServletContext servletContext) {
        String registrationId = (String) servletContext.getAttribute(CONTEXT_REGISTRATION_ID);
        if (!isEmpty(registrationId)) {
            AuthConfigFactory.getFactory().removeRegistration(registrationId);
        }
    }


    // Couple of convenience methods for usage in JSF - may remove these as its too tightly coupled

    public static boolean authenticate() {
        return authenticate(getRequest(), getResponse(), null);
    }

    public static boolean authenticate(AuthParameters authParameters) {
        return authenticate(getRequest(), getResponse(), authParameters);
    }

    public static boolean refreshAuthentication(AuthParameters authParameters) {
        return refreshAuthentication(getRequest(), getResponse(), authParameters);
    }

    public static void logout() {
        logout(getRequest(), getResponse());
    }

    // End Couple of convenience methods for usage in JSF - may remove these as its too tightly coupled

    public static HttpServletRequest getRequest() {
        return (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
    }

    public static HttpServletResponse getResponse() {
        return (HttpServletResponse) FacesContext.getCurrentInstance().getExternalContext().getResponse();
    }


}