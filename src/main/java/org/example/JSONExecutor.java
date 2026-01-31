package org.example;
import java.io.IOException;
import java.net.http.HttpClient;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Scanner;
import java.util.UUID;

import com.fasterxml.jackson.databind.ObjectMapper;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class JSONExecutor {
    private static final ObjectMapper mapper = new ObjectMapper();

    private static String extractVersion(String fileName) {
        int underscoreIndex = fileName.indexOf('-');
        if (underscoreIndex > 0) {
            return fileName.substring(0, underscoreIndex);
        }
        return null;
    }

    private static SSLContext createInsecureSslContext() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        }

                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        }

                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }
                    }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            return sslContext;
        } catch (Exception e) {
            throw new RuntimeException("Failed to ceate SSL Context", e);
        }
    }

    private static String replacePlaceholders(String text, String version, String cardNumber) {
        while (text.contains("${UUID}")) {
            text = text.replaceFirst("\\$\\{UUID\\}", UUID.randomUUID().toString());
        }
        return text.replaceFirst("\\$\\{version\\}", version)
                .replaceAll("\\$\\{CARD_NUMBER\\}", cardNumber);
    }

    private static void formatJsonFile(Path filePath) throws IOException {
        String content = Files.readString(filePath);
        Object json = mapper.readValue(content, Object.class);
        String formattedJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);
        Files.writeString(filePath, formattedJson);
    }

    public static void main( String[] args ) throws IOException {
        try (Scanner scanner = new Scanner(System.in)) {
            Path inputDir = Paths.get("json_curl");
            Path outputDir = Paths.get("json_output");
            Path requestDir = Paths.get("json_request");

            try {
                Files.createDirectories(outputDir);
                Files.createDirectories(requestDir);
            } catch (IOException e) {
                System.err.println("Error creating directories: " + e.getMessage());
                return;
            }

            HttpClient client = HttpClient.newBuilder()
                    .sslContext(createInsecureSslContext())
                    .build();

            try (DirectoryStream<Path> stream = Files.newDirectoryStream(inputDir, "*.curl")) {
                for (Path filePath : stream) {
                    String fileName = filePath.getFileName().toString();
                    String version = extractVersion(fileName);
                    if (version == null) {
                        System.out.println("Skipping " + fileName + ": No version found (expected format: version_name.curl)");
                        continue;
                    }
                    executeJsonRequest(client, filePath.toFile(), version, cardNumber, outputDir, requestDir);
                }
            } catch (IOException e) {
                System.err.println("Error reading input directory: " + e.getMessage());
            }
        }


    }
}
