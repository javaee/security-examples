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

import static javax.security.auth.message.AuthStatus.SEND_SUCCESS;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * https://java.net/jira/browse/JASPIC_SPEC-17
 *
 * A server authentication module (SAM) implementation base class, tailored for the Servlet Container Profile.
 *
 * @author Arjan Tijms
 *
 */
public abstract class HttpServerAuthModule implements ServerAuthModule {

	private CallbackHandler handler;
	private Map<String, String> options;
	private final Class<?>[] supportedMessageTypes = new Class[] { HttpServletRequest.class, HttpServletResponse.class };
	
	@Override
	@SuppressWarnings("unchecked")
	public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, @SuppressWarnings("rawtypes") Map options) throws AuthException {
		this.handler = handler;
		this.options = options;
		initializeModule(new HttpMsgContext(handler, options, null, null));
	}

	/**
	 * A Servlet Container Profile compliant implementation should return HttpServletRequest and HttpServletResponse, so
	 * the delegation class {@link ServerAuthContext} can choose the right SAM to delegate to.
	 */
	@Override
	public Class<?>[] getSupportedMessageTypes() {
		return supportedMessageTypes;
	}

	@Override
	public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
		HttpMsgContext msgContext = new HttpMsgContext(handler, options, messageInfo, clientSubject);
		return validateHttpRequest(msgContext.getRequest(), msgContext.getResponse(), msgContext);
	}

	@Override
	public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
		return SEND_SUCCESS;
	}

	/**
	 * Called in response to a {@link HttpServletRequest#logout()} call.
	 *
	 */
	@Override
	public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
	    HttpMsgContext msgContext = new HttpMsgContext(handler, options, messageInfo, subject);
		cleanHttpSubject(msgContext.getRequest(), msgContext.getResponse(), msgContext);
	}
	
	public void initializeModule(HttpMsgContext httpMsgContext) {
		
	}

	public AuthStatus validateHttpRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) throws AuthException {
		throw new IllegalStateException("Not implemented");
	}

	public void cleanHttpSubject(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) {
	    httpMsgContext.cleanClientSubject();
	}

}