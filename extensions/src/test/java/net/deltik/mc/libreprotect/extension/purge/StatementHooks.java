/*
 * Copyright (C) 2026 Deltik <https://www.deltik.net/>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of LibreProtect.
 *
 * LibreProtect is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LibreProtect is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LibreProtect.  If not, see <https://www.gnu.org/licenses/>.
 */

package net.deltik.mc.libreprotect.extension.purge;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Wraps a connection so a test can see, fail or hold up the statements run
 * on it, and see them canceled.
 */
final class StatementHooks {

    /** Called around statements run on a wrapped connection */
    interface Hook {
        /**
         * Before a statement runs; throw to fail it.
         *
         * @param parameters the values bound so far, in parameter order
         */
        void before(String sql, List<Object> parameters) throws SQLException;

        /** When the statement is canceled, from any thread */
        default void canceled(String sql) {
        }

        /** Before any call on the connection itself, such as setNetworkTimeout */
        default void connection(String method, Object[] arguments) {
        }
    }

    private static final Set<String> EXECUTE = Set.of("execute", "executeQuery", "executeUpdate", "executeLargeUpdate");

    private StatementHooks() {
    }

    static Connection wrap(Connection connection, Hook hook) {
        return proxy(Connection.class, connection, (proxy, method, arguments) -> {
            hook.connection(method.getName(), arguments);
            if (method.getName().equals("setNetworkTimeout")) {
                // SQLite has no network to wait on
                return null;
            }
            Object result = invoke(connection, method, arguments);
            if (method.getName().equals("prepareStatement") && result instanceof PreparedStatement) {
                return statement(PreparedStatement.class, (PreparedStatement) result, hook, (String) arguments[0]);
            }
            if (method.getName().equals("createStatement") && result instanceof Statement) {
                return statement(Statement.class, (Statement) result, hook, null);
            }
            return result;
        });
    }

    private static <T extends Statement> T statement(Class<T> type, T statement, Hook hook, String preparedSql) {
        Map<Integer, Object> parameters = new TreeMap<>();
        return proxy(type, statement, (proxy, method, arguments) -> {
            String sql = preparedSql != null ? preparedSql
                : arguments != null && arguments.length > 0 && arguments[0] instanceof String ? (String) arguments[0] : "";
            if (method.getName().startsWith("set") && arguments != null && arguments.length == 2
                && arguments[0] instanceof Integer) {
                parameters.put((Integer) arguments[0], arguments[1]);
            } else if (EXECUTE.contains(method.getName())) {
                hook.before(sql, List.copyOf(parameters.values()));
            } else if (method.getName().equals("cancel")) {
                hook.canceled(sql);
            }
            return invoke(statement, method, arguments);
        });
    }

    private static Object invoke(Object target, Method method, Object[] arguments) throws Throwable {
        try {
            return method.invoke(target, arguments);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    private static <T> T proxy(Class<T> type, T target, InvocationHandler handler) {
        return type.cast(Proxy.newProxyInstance(StatementHooks.class.getClassLoader(), new Class<?>[]{type}, handler));
    }
}
