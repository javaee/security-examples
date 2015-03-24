package org.secured.jaspic.simple;

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
            asList("RedBaron", "JoeCool", "MansBestFriend" )
        );
    }
}