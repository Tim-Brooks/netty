/*
 * Copyright 2012 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.util;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

public final class SocketUtils {

    private SocketUtils() {
    }

    public static void connect(final Socket socket, final SocketAddress remoteAddress, final int timeout)
            throws Exception {
        try {
            AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
                @Override
                public Void run() throws Exception {
                    socket.connect(remoteAddress, timeout);
                    return null;
                }
            });
        } catch (PrivilegedActionException e) {
            throw (Exception) e.getCause();
        }
    }

    public static boolean connect(final SocketChannel socketChannel, final SocketAddress remoteAddress)
            throws Exception {
        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<Boolean>() {
                @Override
                public Boolean run() throws Exception {
                    return socketChannel.connect(remoteAddress);
                }
            });
        } catch (PrivilegedActionException e) {
            throw (Exception) e.getCause();
        }
    }

    public static SocketChannel accept(final ServerSocketChannel serverSocketChannel) throws Exception {
        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<SocketChannel>() {
                @Override
                public SocketChannel run() throws Exception {
                    return serverSocketChannel.accept();
                }
            });
        } catch (PrivilegedActionException e) {
            throw (Exception) e.getCause();
        }
    }

    public static InetSocketAddress socketAddress(final String hostname, final int port) {

        return AccessController.doPrivileged(new PrivilegedAction<InetSocketAddress>() {
            @Override
            public InetSocketAddress run() {
                return new InetSocketAddress(hostname, port);
            }
        });
    }
}
