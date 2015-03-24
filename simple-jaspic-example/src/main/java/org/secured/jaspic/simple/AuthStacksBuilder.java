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

import javax.security.auth.message.module.ServerAuthModule;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.util.Arrays.asList;
import static org.secured.jaspic.simple.ServiceType.AUTO_REGISTER_SESSION;
import static org.secured.jaspic.simple.ServiceType.REMEMBER_ME;
import static org.secured.jaspic.simple.ServiceType.SAVE_AND_REDIRECT;

public class AuthStacksBuilder {

    private boolean logAuthExceptions = true;
    private AuthStacks authStacks = new AuthStacks();

    public StackBuilder stack() {
        return new StackBuilder();
    }

    public AuthStacksBuilder logAuthExceptions(boolean logAuthExceptions) {
        this.logAuthExceptions = logAuthExceptions;
        return this;
    }

    public AuthStacks build() {
        // If there's no default, take first.
        if (authStacks.getDefaultStackName() == null && authStacks.getModuleStacks().size() > 0) {
            authStacks.setDefaultStackName(authStacks.getModuleStacks().keySet().iterator().next());
        }

        authStacks.setLogAuthExceptions(logAuthExceptions);

        return authStacks;
    }

    public class StackBuilder {

        String name;
        boolean isDefault;
        List<Module> modules = new ArrayList<>();

        public StackBuilder name(String name) {
            this.name = name;
            return this;
        }

        public StackBuilder setDefault() {
            isDefault = true;
            return this;
        }

        public ModuleBuilder module() {
            return new ModuleBuilder();
        }

        public AuthStacksBuilder add() {
            if (name == null) {
                name = UUID.randomUUID().toString();
            }
            if (isDefault) {
                authStacks.setDefaultStackName(name);
            }
            authStacks.getModuleStacks().put(name, modules);
            return AuthStacksBuilder.this;
        }

        public class ModuleBuilder {

            private Module module = new Module();
            private Map<String, String> options = new HashMap<String, String>();

            public ModuleBuilder serverAuthModule(ServerAuthModule serverAuthModule) {

                ServerAuthModule wrappedServerAuthModule = serverAuthModule;

                if (serverAuthModule.getClass().isAnnotationPresent(SamServices.class)) {
                    List<ServiceType> types = asList(serverAuthModule.getClass().getAnnotation(SamServices.class).value());

                    if (types.contains(SAVE_AND_REDIRECT)) {
                        wrappedServerAuthModule = new SaveAndRedirectWrapper(wrappedServerAuthModule);
                    }

                    if (types.contains(REMEMBER_ME)) {
                        wrappedServerAuthModule = new RememberMeWrapper(wrappedServerAuthModule);
                    }

                    if (types.contains(AUTO_REGISTER_SESSION)) {
                        wrappedServerAuthModule = new AutoRegisterSessionWrapper(wrappedServerAuthModule);
                    }
                }

                module.setServerAuthModule(wrappedServerAuthModule);
                return this;
            }

            public ModuleBuilder controlFlag(ControlFlag controlFlag) {
                module.setControlFlag(controlFlag);
                return this;
            }

            public ModuleBuilder options(Map<String, String> options) {
                this.options.putAll(options);
                return this;
            }

            public ModuleBuilder option(String key, String value) {
                options.put(key, value);
                return this;
            }

            public StackBuilder add() {
                module.setOptions(options);
                modules.add(module);
                return StackBuilder.this;
            }
        }
    }
}