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

/**
 * Parameters that are provided along with an authentication request.
 *
 * @author Arjan Tijms
 *
 */
public class AuthParameters {

	private String username;
	private String password;
	private Boolean rememberMe;
	private Boolean noPassword;
	private String authMethod;

	private String redirectUrl;

	public AuthParameters username(String username) {
		setUsername(username);
		return this;
	}

	public AuthParameters password(String passWord) {
		setPassword(passWord);
		return this;
	}

	public AuthParameters rememberMe(boolean rememberMe) {
		setRememberMe(rememberMe);
		return this;
	}
	
	public AuthParameters noPassword(boolean noPassword) {
		setNoPassword(noPassword);
		return this;
	}

	public AuthParameters authMethod(String authMethod) {
		setAuthMethod(authMethod);
		return this;
	}

	public AuthParameters redirectUrl(String redirectUrl) {
		setRedirectUrl(redirectUrl);
		return this;
	}

	// Getters/setters

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public Boolean getRememberMe() {
		return rememberMe;
	}

	public void setRememberMe(Boolean rememberMe) {
		this.rememberMe = rememberMe;
	}

	public String getAuthMethod() {
		return authMethod;
	}

	public void setAuthMethod(String authMethod) {
		this.authMethod = authMethod;
	}

	public String getRedirectUrl() {
		return redirectUrl;
	}

	public void setRedirectUrl(String redirectUrl) {
		this.redirectUrl = redirectUrl;
	}

	public Boolean getNoPassword() {
		return noPassword;
	}

	public void setNoPassword(Boolean noPassword) {
		this.noPassword = noPassword;
	}

}