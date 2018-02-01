/*
 * Copyright (c) 2015-2018 Oracle and/or its affiliates. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Oracle nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.superbiz.injection.secure;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.annotation.security.RunAs;
import javax.ejb.EJB;
import javax.ejb.EJBAccessException;
import javax.ejb.Stateless;
import javax.ejb.embeddable.EJBContainer;
import java.util.List;
import java.util.Properties;

//START SNIPPET: code

public class MovieTest {

    @EJB
    private Movies movies;

    @EJB(name = "ManagerBean")
    private ManagerBean manager;

    @EJB(name = "EmployeeBean")
    private EmployeeBean employee;

    private EJBContainer container;

    @Before
    public void setUp() throws Exception {
        Properties p = new Properties();
        p.put("movieDatabase", "new://Resource?type=DataSource");
        p.put("movieDatabase.JdbcDriver", "org.hsqldb.jdbcDriver");
        p.put("movieDatabase.JdbcUrl", "jdbc:hsqldb:mem:moviedb");

        this.container = EJBContainer.createEJBContainer(p);
        this.container.getContext().bind("inject", this);
    }

    @After
    public void tearDown() {
        this.container.close();
    }

    @Test
    public void testAsManager() throws Exception {
        manager.run(() -> {

            movies.addMovie(new Movie("Quentin Tarantino", "Reservoir Dogs", 1992));
            movies.addMovie(new Movie("Joel Coen", "Fargo", 1996));
            movies.addMovie(new Movie("Joel Coen", "The Big Lebowski", 1998));

            List<Movie> list = movies.getMovies();
            Assert.assertEquals("List.size()", 3, list.size());

            for (Movie movie : list) {
                movies.deleteMovie(movie);
            }

            Assert.assertEquals("Movies.getMovies()", 0, movies.getMovies().size());
        });
    }

    @Test
    public void testAsEmployee() throws Exception {
        employee.run(() -> {

            movies.addMovie(new Movie("Quentin Tarantino", "Reservoir Dogs", 1992));
            movies.addMovie(new Movie("Joel Coen", "Fargo", 1996));
            movies.addMovie(new Movie("Joel Coen", "The Big Lebowski", 1998));

            List<Movie> list = movies.getMovies();
            Assert.assertEquals("List.size()", 3, list.size());

            for (Movie movie : list) {
                try {
                    movies.deleteMovie(movie);
                    Assert.fail("Employees should not be allowed to delete");
                } catch (EJBAccessException e) {
                    // Good, Employees cannot delete things
                }
            }

            // The list should still be three movies long
            Assert.assertEquals("Movies.getMovies()", 3, movies.getMovies().size());
        });
    }

    @Test
    public void testUnauthenticated() throws Exception {
        try {
            movies.addMovie(new Movie("Quentin Tarantino", "Reservoir Dogs", 1992));
            Assert.fail("Unauthenticated users should not be able to add movies");
        } catch (EJBAccessException e) {
            // Good, guests cannot add things
        }

        try {
            movies.deleteMovie(null);
            Assert.fail("Unauthenticated users should not be allowed to delete");
        } catch (EJBAccessException e) {
            // Good, Unauthenticated users cannot delete things
        }

        try {
            // Read access should be allowed

            movies.getMovies();

        } catch (EJBAccessException e) {
            Assert.fail("Read access should be allowed");
        }

    }

    /**
     * This little bit of magic allows our test code to execute in
     * the desired security scope.
     */

    @Stateless
    @RunAs("Manager")
    public static class ManagerBean  {
        public void run(Callable callable) throws Exception {
            callable.call();
        }
    }

    @Stateless
    @RunAs("Employee")
    public static class EmployeeBean {
        public void run(Callable callable) throws Exception {
            callable.call();
        }
    }

    public interface Callable {
        void call() throws Exception;
    }

}
//END SNIPPET: code
