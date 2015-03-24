package org.secured;

import java.security.Principal;

public class UserPrincipal implements Principal {
    private final String name;

    public UserPrincipal(String name) {
        if(name == null) {
            throw new IllegalArgumentException("name cannot be null");
        } else {
            this.name = name;
        }
    }

    public String getName() {
        return this.name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) { return true; }
        if (o == null || getClass() != o.getClass()) { return false; }

        UserPrincipal that = (UserPrincipal) o;

        if (!name.equals(that.name)) { return false; }

        return true;
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }

    @Override
    public String toString() {
        return "UserPrincipal{" +
                "name='" + name + '\'' +
                '}';
    }
}
