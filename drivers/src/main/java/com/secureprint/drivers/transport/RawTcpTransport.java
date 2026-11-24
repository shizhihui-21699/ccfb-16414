package com.secureprint.drivers.transport;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import com.secureprint.drivers.spi.DeviceSession;
import com.secureprint.drivers.spi.DriverException;

/**
 * Raw TCP transport helpers: the common "socket 9100" JetDirect-style path that nearly every
 * network printer still exposes, plus a PJL status query.
 *
 * <p>Kept transport-only so it can be unit-tested against a loopback server without any real
 * device, and so every driver that speaks raw TCP shares one hardened implementation (connect
 * timeouts, no half-open sockets, bounded writes).
 */
public final class RawTcpTransport {

    private RawTcpTransport() {
    }

    /**
     * Sends {@code payload} and half-closes; returns bytes written.
     *
     * <p>{@code SO_TIMEOUT} only bounds reads, so a printer whose TCP receive window has filled
     * (jam, hung firmware, half-open link) can block {@code write()} indefinitely and wedge the
     * release thread. A watchdog closes the socket at the deadline, which turns the blocked write
     * into a {@link java.net.SocketException} and keeps the caller's latency bounded.
     */
    public static int send(DeviceSession session, byte[] payload) {
        try (Socket socket = connect(session)) {
            Thread watchdog = startWatchdog(socket, session.timeoutMillis());
            try {
                OutputStream out = socket.getOutputStream();
                out.write(payload);
                out.flush();
                socket.shutdownOutput();
                return payload.length;
            } finally {
                watchdog.interrupt();
            }
        } catch (IOException e) {
            throw new DriverException("raw-tcp", "send to " + session.host() + ":"
                    + session.port() + " failed: " + e.getMessage(), false, e);
        }
    }

    private static Thread startWatchdog(Socket socket, int timeoutMillis) {
        Thread t = new Thread(() -> {
            try {
                Thread.sleep(timeoutMillis);
                socket.close();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (IOException ignored) {
                // Socket already closed by the normal path.
            }
        }, "printer-write-watchdog");
        t.setDaemon(true);
        t.start();
        return t;
    }

    /**
     * Issues a PJL status query and reads the reply until the printer's status marker.
     *
     * <p>PJL is the only status mechanism common to PCL devices. We send a Universal Exit
     * Language, enter PJL, ask for status, and read back the human-readable keyword string.
     * A device that does not implement PJL simply times out and is reported OFFLINE — better a
     * false negative than a stalled release.
     */
    public static String pjlStatus(DeviceSession session) {
        String query = "\u001B%-12345X@PJL INFO STATUS\r\n\u001B%-12345X";
        try (Socket socket = connect(session)) {
            socket.setSoTimeout(session.timeoutMillis());
            OutputStream out = socket.getOutputStream();
            out.write(query.getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            socket.shutdownOutput();
            return readAll(socket, session.timeoutMillis());
        } catch (IOException e) {
            throw new DriverException("pjl", "PJL status failed: " + e.getMessage(), false, e);
        }
    }

    private static Socket connect(DeviceSession session) throws IOException {
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(session.host(), session.port()),
                    session.timeoutMillis());
            socket.setSoTimeout(session.timeoutMillis());
            socket.setTcpNoDelay(true);
            return socket;
        } catch (IOException e) {
            socket.close();
            throw e;
        }
    }

    private static String readAll(Socket socket, int timeoutMillis) throws IOException {
        StringBuilder sb = new StringBuilder();
        byte[] buf = new byte[1024];
        long deadline = System.nanoTime() + timeoutMillis * 1_000_000L;
        try {
            int n;
            while ((n = socket.getInputStream().read(buf)) > 0) {
                sb.append(new String(buf, 0, n, StandardCharsets.ISO_8859_1));
                if (System.nanoTime() > deadline) {
                    break;
                }
            }
        } catch (java.net.SocketTimeoutException e) {
            // Partial status is still useful; fall through.
        }
        return sb.toString();
    }
}
