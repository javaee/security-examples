package org.secured.jaspic.simple;

import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;

public class Provider extends HttpServerAuthModule {
    
    @Override
    public AuthStatus validateHttpRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) throws AuthException {
        // Communicate the details of the authenticated user to the container. In many
        // cases the handler will just store the details and the container will actually handle
        // the login after we return from this method.
        return httpMsgContext.notifyContainerAboutLogin(
            // The name of the authenticated user
            "snoopy",
            // the groups/roles of the authenticated user
            Arrays.asList("RedBaron", "JoeCool", "MansBestFriend")
        );
    }
}