package io.github.authme.fabric;

import io.github.authme.fabric.config.AuthMeConfig;
import io.github.authme.fabric.mail.EmailSender;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Small local SMTP protocol regression test; it never contacts an external mail service. */
public final class MailSelfTest {

    private MailSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("authme-mail-selftest-");
        try (ServerSocket server = new ServerSocket(0)) {
            Files.writeString(directory.resolve("config.yml"), """
                Email:
                    enabled: true
                    host: '127.0.0.1'
                    port: %d
                    from: 'sender@example.test'
                    ssl: false
                    startTls: false
                    timeoutMillis: 2000
                """.formatted(server.getLocalPort()), StandardCharsets.UTF_8);

            AuthMeConfig config = new AuthMeConfig(directory);
            require(config.load(), "SMTP test config should load");
            AtomicBoolean sawDotStuffedBody = new AtomicBoolean();
            AtomicBoolean sawTerminator = new AtomicBoolean();
            AtomicReference<Throwable> serverFailure = new AtomicReference<>();
            Thread smtp = new Thread(() -> serve(server, sawDotStuffedBody, sawTerminator, serverFailure),
                "authme-mail-selftest-smtp");
            smtp.start();

            boolean sent = EmailSender.send(config, "recipient@example.test", "AuthMe test", "hello\n.leading");
            server.close();
            smtp.join(5000);
            require(sent, "SMTP send should succeed");
            require(sawDotStuffedBody.get(), "SMTP body lines beginning with a dot must be stuffed");
            require(sawTerminator.get(), "SMTP DATA must end with an unstuffed terminator");
            require(serverFailure.get() == null, "SMTP test server failed: " + serverFailure.get());
        }
        System.out.println("AuthMe mail self-test passed.");
    }

    private static void serve(ServerSocket server, AtomicBoolean sawDotStuffedBody,
                              AtomicBoolean sawTerminator, AtomicReference<Throwable> failure) {
        try (Socket socket = server.accept();
             BufferedReader reader = new BufferedReader(
                 new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
             BufferedWriter writer = new BufferedWriter(
                 new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.US_ASCII))) {
            reply(writer, "220 authme-test");
            boolean data = false;
            String line;
            while ((line = reader.readLine()) != null) {
                if (data) {
                    if (line.equals(".")) {
                        sawTerminator.set(true);
                        data = false;
                        reply(writer, "250 queued");
                    } else if (line.equals("..leading")) {
                        sawDotStuffedBody.set(true);
                    }
                    continue;
                }
                String command = line.toUpperCase(Locale.ROOT);
                if (command.startsWith("EHLO")) {
                    writer.write("250-authme-test\r\n250 AUTH PLAIN\r\n");
                    writer.flush();
                } else if (command.startsWith("MAIL FROM:")) {
                    reply(writer, "250 sender ok");
                } else if (command.startsWith("RCPT TO:")) {
                    reply(writer, "250 recipient ok");
                } else if (command.equals("DATA")) {
                    data = true;
                    reply(writer, "354 send it");
                } else if (command.equals("QUIT")) {
                    reply(writer, "221 bye");
                    return;
                } else {
                    throw new IllegalStateException("Unexpected SMTP command: " + line);
                }
            }
        } catch (Throwable e) {
            if (!(e instanceof java.net.SocketException && server.isClosed())) {
                failure.set(e);
            }
        }
    }

    private static void reply(BufferedWriter writer, String line) throws Exception {
        writer.write(line);
        writer.write("\r\n");
        writer.flush();
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
