package ru.firewall;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class FtpProxyTest {
    @Test public void pasvRelayDownloadsContentsAndRejectsOtherClients() throws Exception {
        passiveDownload(false);
    }

    @Test public void epsvRelayDownloadsContentsAndRejectsOtherClients() throws Exception {
        passiveDownload(true);
    }

    private void passiveDownload(boolean extended) throws Exception {
        InetAddress localhost = InetAddress.getByAddress(new byte[]{127, 0, 0, 1});
        byte[] binary = {11, -15, 0, 48, 13, 10, 1};
        var fakeServer = Executors.newSingleThreadExecutor();
        try (ServerSocket server = listen(localhost); ServerSocket dataServer = listen(localhost)) {
            int proxyPort;
            int proxyDataPort;
            try (ServerSocket controlLease = listen(localhost); ServerSocket dataLease = listen(localhost)) {
                proxyPort = controlLease.getLocalPort();
                proxyDataPort = dataLease.getLocalPort();
            }
            int backendPort = dataServer.getLocalPort();
            FtpSettings settings = FtpSettings.parse("Home", "127.0.0.1/32", "" + proxyPort,
                    "" + proxyDataPort, "" + server.getLocalPort(), "" + backendPort);
            var served = fakeServer.submit(() -> {
                try (Socket control = server.accept()) {
                    control.setSoTimeout(3000);
                    BufferedReader commands = reader(control);
                    write(control, "220 Explorer");
                    assertEquals(extended ? "EPSV" : "PASV", commands.readLine());
                    write(control, extended ? "229 Entering Extended Passive Mode (!!!" + backendPort + "!)"
                            : "227 Entering Passive Mode (203,0,113,9," + (backendPort >> 8)
                            + "," + (backendPort & 255) + ")");
                    assertEquals("RETR test.bin", commands.readLine());
                    write(control, "150 Opening data connection");
                    try (Socket data = dataServer.accept()) {
                        data.getOutputStream().write(binary);
                    }
                    write(control, "226 Transfer complete");
                    assertEquals("QUIT", commands.readLine());
                    write(control, "221 Bye");
                }
                return null;
            });
            AtomicBoolean atHome = new AtomicBoolean(true);
            try (FtpProxy proxy = new FtpProxy(settings, localhost, atHome::get)) {
                try (Socket rejected = new Socket()) {
                    rejected.bind(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127, 0, 0, 2}), 0));
                    rejected.connect(new InetSocketAddress(localhost, proxyPort));
                    rejected.setSoTimeout(3000);
                    assertEquals(-1, rejected.getInputStream().read());
                }
                try (Socket control = connect(localhost, proxyPort)) {
                    BufferedReader responses = reader(control);
                    assertEquals("220 Explorer", responses.readLine());
                    write(control, "PORT 127,0,0,1,1,9");
                    assertTrue(responses.readLine().startsWith("502 "));
                    write(control, extended ? "EPSV" : "PASV");
                    assertEquals(extended ? "229 Entering Extended Passive Mode (|||" + proxyDataPort + "|)"
                            : "227 Entering Passive Mode (127,0,0,1," + (proxyDataPort >> 8)
                            + "," + (proxyDataPort & 255) + ")", responses.readLine());
                    try (Socket rejectedData = new Socket()) {
                        rejectedData.bind(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127, 0, 0, 2}), 0));
                        rejectedData.connect(new InetSocketAddress(localhost, proxyDataPort));
                        rejectedData.setSoTimeout(3000);
                        assertEquals(-1, rejectedData.getInputStream().read());
                    }
                    try (Socket data = connect(localhost, proxyDataPort)) {
                        write(control, "RETR test.bin");
                        assertTrue(responses.readLine().startsWith("150 "));
                        assertArrayEquals(binary, data.getInputStream().readAllBytes());
                    }
                    assertTrue(responses.readLine().startsWith("226 "));
                    write(control, "QUIT");
                    assertEquals("221 Bye", responses.readLine());
                }
                served.get(3, TimeUnit.SECONDS);
                atHome.set(false);
                try (Socket outside = connect(localhost, proxyPort)) {
                    assertEquals(-1, outside.getInputStream().read());
                }
            }
        } finally {
            fakeServer.shutdownNow();
        }
    }

    private static ServerSocket listen(InetAddress address) throws IOException {
        ServerSocket listener = new ServerSocket(0, 4, address);
        listener.setSoTimeout(3000);
        return listener;
    }

    private static Socket connect(InetAddress host, int port) throws IOException {
        Socket socket = new Socket(host, port);
        socket.setSoTimeout(3000);
        return socket;
    }

    private static void write(Socket socket, String line) throws IOException {
        OutputStream output = socket.getOutputStream();
        output.write((line + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
        output.flush();
    }

    private static BufferedReader reader(Socket socket) throws IOException {
        return new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.ISO_8859_1));
    }
}
