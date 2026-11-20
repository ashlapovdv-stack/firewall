package ru.firewall;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.function.BooleanSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Passive FTP bridge. Both control and data sockets are limited to the selected Wi-Fi address. */
final class FtpProxy implements Closeable {
    private static final Pattern PASV = Pattern.compile("\\((\\d{1,3}),(\\d{1,3}),(\\d{1,3}),(\\d{1,3}),(\\d{1,3}),(\\d{1,3})\\)");
    private static final Pattern EPSV = Pattern.compile("\\(([^0-9])\\1\\1(\\d{1,5})\\1\\)");
    private static final int MAX_LINE = 8192;
    private static final int DATA_WAIT = 30_000;
    private static final int TRANSFER_IDLE = 180_000;
    private final FtpSettings settings;
    private final InetAddress wifiAddress;
    private final InetAddress loopback;
    private final BooleanSupplier homeNetwork;
    private final ServerSocket listener;
    private final ExecutorService workers = Executors.newCachedThreadPool();
    private final Semaphore controlSlots = new Semaphore(8);
    private final Set<Closeable> open = ConcurrentHashMap.newKeySet();
    private volatile boolean closed;

    FtpProxy(FtpSettings settings, InetAddress wifiAddress, BooleanSupplier homeNetwork) throws IOException {
        this.settings = settings;
        this.wifiAddress = wifiAddress;
        this.homeNetwork = homeNetwork;
        loopback = InetAddress.getByAddress(new byte[]{127, 0, 0, 1});
        listener = listen(settings.port());
        workers.execute(this::acceptClients);
    }

    private ServerSocket listen(int port) throws IOException {
        ServerSocket socket = new ServerSocket();
        try {
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(wifiAddress, port), 8);
            return track(socket);
        } catch (IOException failure) {
            close(socket);
            throw failure;
        }
    }

    private <T extends Closeable> T track(T socket) throws IOException {
        open.add(socket);
        if (closed) {
            closeTracked(socket);
            throw new IOException("FTP proxy stopped");
        }
        return socket;
    }

    private void acceptClients() {
        while (!closed) {
            Socket client;
            try {
                client = listener.accept();
                track(client);
            } catch (IOException stopped) {
                return;
            }
            if (!settings.clients().contains(client.getInetAddress()) || !homeNetwork.getAsBoolean()
                    || !controlSlots.tryAcquire()) {
                closeTracked(client);
                continue;
            }
            try {
                workers.execute(() -> {
                    try {
                        control(client);
                    } finally {
                        controlSlots.release();
                    }
                });
            } catch (RejectedExecutionException stopped) {
                controlSlots.release();
                closeTracked(client);
            }
        }
    }

    private Socket localServer(int port, InetAddress preferred) throws IOException {
        Socket socket = track(new Socket());
        try {
            // The original server can listen on localhost, or exclusively on the phone's Wi-Fi address.
            socket.connect(new InetSocketAddress(preferred, port), 3000);
            return socket;
        } catch (IOException failure) {
            closeTracked(socket);
            throw failure;
        }
    }

    private Socket controlServer() throws IOException {
        try {
            return localServer(settings.serverPort(), loopback);
        } catch (IOException unavailableOnLoopback) {
            return localServer(settings.serverPort(), wifiAddress);
        }
    }

    private void control(Socket client) {
        Socket backend = null;
        DataSession data = null;
        try {
            backend = controlServer();
            client.setSoTimeout(600_000);
            backend.setSoTimeout(600_000);
            InputStream requests = new BufferedInputStream(client.getInputStream());
            InputStream responses = new BufferedInputStream(backend.getInputStream());
            Lines toClient = new Lines(client.getOutputStream());
            Lines toServer = new Lines(backend.getOutputStream());
            InetAddress peer = client.getInetAddress();
            InetAddress serverAddress = backend.getInetAddress();
            data = new DataSession(peer, serverAddress);
            Socket upstream = backend;
            workers.execute(() -> sendCommands(client, upstream, requests, toClient, toServer));
            String line;
            while ((line = readLine(responses)) != null && homeNetwork.getAsBoolean()) {
                if (line.startsWith("227 ") || line.startsWith("229 ")) {
                    line = data.rewrite(line);
                }
                toClient.write(line);
            }
        } catch (IOException | RejectedExecutionException stopped) {
            // Closing the sockets also stops the command and data relays.
        } finally {
            if (data != null) data.close();
            closeTracked(backend);
            closeTracked(client);
        }
    }

    private void sendCommands(Socket client, Socket backend, InputStream requests, Lines toClient, Lines toServer) {
        try {
            String line;
            while ((line = readLine(requests)) != null && homeNetwork.getAsBoolean()) {
                String command = line.trim().split("[ \\t]", 2)[0].toUpperCase(Locale.ROOT);
                if (command.equals("PORT") || command.equals("EPRT") || command.equals("AUTH")
                        || command.equals("CCC") || command.equals("PBSZ") || command.equals("PROT")) {
                    toClient.write("502 Passive FTP without TLS is required");
                } else {
                    toServer.write(line);
                }
            }
        } catch (IOException stopped) {
            // The control connection ended.
        } finally {
            closeTracked(client);
            closeTracked(backend);
        }
    }

    private final class DataSession implements Closeable {
        private final InetAddress peer;
        private final InetAddress serverAddress;
        private final Set<Closeable> dataSockets = ConcurrentHashMap.newKeySet();
        private ServerSocket pending;
        private volatile boolean finished;
        private volatile long generation;

        DataSession(InetAddress peer, InetAddress serverAddress) {
            this.peer = peer;
            this.serverAddress = serverAddress;
        }

        String rewrite(String line) {
            boolean extended = line.startsWith("229 ");
            int serverPort = passivePort(line, extended);
            long transfer = ++generation;
            closePending();
            closeDataSockets();
            if (!settings.serverDataPorts().contains(serverPort)) return "425 Passive port outside configured range";
            try {
                ServerSocket external = availableDataPort();
                pending = external;
                int port = external.getLocalPort();
                workers.execute(() -> acceptData(external, serverPort, transfer));
                if (extended) return "229 Entering Extended Passive Mode (|||" + port + "|)";
                String address = wifiAddress.getHostAddress().replace('.', ',');
                return "227 Entering Passive Mode (" + address + "," + (port >> 8) + "," + (port & 255) + ")";
            } catch (IOException | RejectedExecutionException unavailable) {
                closePending();
                return "425 No FTP proxy data port available";
            }
        }

        private ServerSocket availableDataPort() throws IOException {
            for (int port = settings.dataPorts().first(); port <= settings.dataPorts().last(); port++) {
                ServerSocket candidate = null;
                try {
                    candidate = listen(port);
                    candidate.setSoTimeout(DATA_WAIT);
                    return candidate;
                } catch (IOException busy) {
                    closeTracked(candidate);
                }
            }
            throw new IOException("No data port available");
        }

        private void acceptData(ServerSocket external, int serverPort, long transfer) {
            Socket client = null;
            Socket backend = null;
            try {
                long deadline = System.nanoTime() + DATA_WAIT * 1_000_000L;
                while (transfer == generation && !finished && homeNetwork.getAsBoolean()) {
                    long left = (deadline - System.nanoTime()) / 1_000_000L;
                    if (left <= 0) break;
                    external.setSoTimeout((int) left);
                    Socket candidate = external.accept();
                    if (peer.equals(candidate.getInetAddress())) {
                        client = track(candidate);
                        dataSockets.add(client);
                        break;
                    }
                    FtpProxy.close(candidate);
                }
                closeTracked(external);
                if (client == null || transfer != generation || finished || !homeNetwork.getAsBoolean()) return;
                backend = localServer(serverPort, serverAddress);
                dataSockets.add(backend);
                if (transfer != generation || finished || !homeNetwork.getAsBoolean()) return;
                client.setSoTimeout(TRANSFER_IDLE);
                backend.setSoTimeout(TRANSFER_IDLE);
                Socket local = client;
                Socket upstream = backend;
                var upload = workers.submit(() -> copyData(local, upstream));
                copyData(upstream, local);
                try {
                    upload.get();
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                } catch (java.util.concurrent.ExecutionException ended) {
                    // Both directions are closed below.
                }
            } catch (SocketTimeoutException timeout) {
                // No data connection was made in time.
            } catch (IOException | RejectedExecutionException stopped) {
                // End the data connection if either socket fails.
            } finally {
                closeTracked(external);
                releaseData(client);
                releaseData(backend);
            }
        }

        private void releaseData(Socket socket) {
            if (socket == null) return;
            dataSockets.remove(socket);
            closeTracked(socket);
        }

        private void closePending() {
            closeTracked(pending);
            pending = null;
        }

        private void closeDataSockets() {
            for (Closeable socket : dataSockets) {
                dataSockets.remove(socket);
                closeTracked(socket);
            }
        }

        @Override public void close() {
            finished = true;
            closePending();
            closeDataSockets();
        }
    }

    private static void copyData(Socket from, Socket to) {
        try {
            byte[] buffer = new byte[16_384];
            InputStream input = from.getInputStream();
            OutputStream output = to.getOutputStream();
            int count;
            while ((count = input.read(buffer)) != -1) output.write(buffer, 0, count);
            to.shutdownOutput();
        } catch (IOException ended) {
            close(from);
            close(to);
        }
    }

    private static int passivePort(String line, boolean extended) {
        Matcher match = (extended ? EPSV : PASV).matcher(line);
        if (!match.find()) return -1;
        if (extended) return Integer.parseInt(match.group(2));
        int high = Integer.parseInt(match.group(5));
        int low = Integer.parseInt(match.group(6));
        return high <= 255 && low <= 255 ? high * 256 + low : -1;
    }

    private static String readLine(InputStream source) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream(128);
        for (int i = 0; i < MAX_LINE; i++) {
            int next = source.read();
            if (next == -1) return null;
            if (next == '\n') {
                byte[] bytes = line.toByteArray();
                int end = bytes.length;
                if (end > 0 && bytes[end - 1] == '\r') end--;
                return new String(bytes, 0, end, StandardCharsets.ISO_8859_1);
            }
            if (next == '\r') {
                if (source.read() != '\n') throw new IOException("Invalid FTP line");
                return new String(line.toByteArray(), StandardCharsets.ISO_8859_1);
            }
            if (next < 32 && next != '\t') throw new IOException("Invalid FTP line");
            line.write(next);
        }
        throw new IOException("FTP line too long");
    }

    private static final class Lines {
        private final BufferedOutputStream out;

        Lines(OutputStream out) { this.out = new BufferedOutputStream(out); }

        synchronized void write(String line) throws IOException {
            out.write(line.getBytes(StandardCharsets.ISO_8859_1));
            out.write('\r');
            out.write('\n');
            out.flush();
        }
    }

    private void closeTracked(Closeable socket) {
        if (socket == null) return;
        open.remove(socket);
        close(socket);
    }

    private static void close(Closeable socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
            // Another relay thread may already have closed the socket.
        }
    }

    @Override public void close() {
        closed = true;
        for (Closeable socket : open) closeTracked(socket);
        workers.shutdownNow();
    }
}
