package io.github.authme.fabric.mail;

import io.github.authme.fabric.config.AuthMeConfig;
import io.github.authme.fabric.util.Log;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Minimal SMTP client using only the JDK, with STARTTLS and implicit TLS support. */
public final class EmailSender {

    private EmailSender() {
    }

    public static boolean send(AuthMeConfig config, String recipient, String subject, String body) {
        if (!config.emailEnabled() || !validHeaderValue(recipient) || !validHeaderValue(subject)) return false;
        String from = config.emailFrom();
        if (!validHeaderValue(from)) return false;
        String configuredSubject = config.emailSubject();
        String effectiveSubject = configuredSubject == null || configuredSubject.isBlank()
            || "AuthMe".equals(configuredSubject) ? subject : configuredSubject;
        if (!validHeaderValue(effectiveSubject)) return false;
        String fromHeader = fromHeader(config, from);
        Socket socket = null;
        try {
            SSLSocketFactory sslFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            socket = config.emailSsl()
                ? sslFactory.createSocket()
                : new Socket();
            socket.connect(new InetSocketAddress(config.emailHost(), config.emailPort()), config.emailTimeoutMillis());
            socket.setSoTimeout(config.emailTimeoutMillis());
            if (socket instanceof SSLSocket ssl) ssl.startHandshake();
            Smtp smtp = new Smtp(socket);
            smtp.expect(220);
            smtp.command("EHLO authme-fabric", 250);
            if (config.emailStartTls() && !config.emailSsl()) {
                smtp.command("STARTTLS", 220);
                SSLSocket tls = (SSLSocket) sslFactory.createSocket(
                    socket, config.emailHost(), config.emailPort(), true);
                tls.setSoTimeout(config.emailTimeoutMillis());
                tls.startHandshake();
                socket = tls;
                smtp = new Smtp(socket);
                smtp.command("EHLO authme-fabric", 250);
            }
            if (!config.emailUsername().isBlank()) {
                smtp.command("AUTH LOGIN", 334);
                smtp.command(Base64.getEncoder().encodeToString(config.emailUsername().getBytes(StandardCharsets.UTF_8)), 334);
                smtp.command(Base64.getEncoder().encodeToString(config.emailPassword().getBytes(StandardCharsets.UTF_8)), 235);
            }
            smtp.command("MAIL FROM:<" + from + ">", 250);
            smtp.command("RCPT TO:<" + recipient + ">", 250, 251);
            smtp.command("DATA", 354);
            smtp.writeData("From: " + fromHeader + "\r\nTo: " + recipient + "\r\nSubject: " + effectiveSubject
                + "\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body);
            smtp.expect(250);
            smtp.command("QUIT", 221, 250);
            return true;
        } catch (Exception e) {
            Log.error("Could not send AuthMe e-mail", e);
            return false;
        } finally {
            if (socket != null) try { socket.close(); } catch (IOException ignored) { }
        }
    }

    private static boolean validHeaderValue(String value) {
        return value != null && !value.isBlank() && value.indexOf('\r') < 0 && value.indexOf('\n') < 0;
    }

    private static String fromHeader(AuthMeConfig config, String address) {
        String name = config.emailSenderName();
        if (!validHeaderValue(name) || name.indexOf('"') >= 0 || name.indexOf('<') >= 0 || name.indexOf('>') >= 0) {
            return address;
        }
        return "\"" + name + "\" <" + address + ">";
    }

    private static final class Smtp {
        private final BufferedReader reader;
        private final BufferedWriter writer;

        private Smtp(Socket socket) throws IOException {
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
            writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.US_ASCII));
        }

        private void command(String value, int... expected) throws IOException {
            writer.write(value);
            writer.write("\r\n");
            writer.flush();
            expect(expected);
        }

        private void writeData(String value) throws IOException {
            for (String line : value.replace("\r\n", "\n").replace('\r', '\n').split("\n", -1)) {
                if (line.startsWith(".")) writer.write('.');
                writer.write(line);
                writer.write("\r\n");
            }
            // The DATA terminator is a protocol marker, not a body line, so it must not be
            // dot-stuffed like a body line that happens to begin with '.'.
            writer.write(".\r\n");
            writer.flush();
        }

        private void expect(int... expected) throws IOException {
            String line;
            int code;
            do {
                line = reader.readLine();
                if (line == null || line.length() < 3) throw new IOException("SMTP closed the connection");
                try { code = Integer.parseInt(line.substring(0, 3)); }
                catch (NumberFormatException e) { throw new IOException("Invalid SMTP response", e); }
            } while (line.length() > 3 && line.charAt(3) == '-');
            for (int value : expected) if (code == value) return;
            throw new IOException("Unexpected SMTP response " + code);
        }
    }
}
