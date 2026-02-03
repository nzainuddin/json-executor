package org.example;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    private static void executeJsonRequest(HttpClient client, File file, String version, String cardNumber, Path outputDir, Path requestDir) throws IOException {
        try {
            String content = Files.readString(file.toPath());
            String originalUrl = findMatch(content, "(?s)--url\\s+([^\\\\\\n]+)");
            if (originalUrl == null || originalUrl.isEmpty()) {
                System.out.println("Error processing " + file.getName() + ": URL not found");
                return;
            }
            String url = replacePlaceholders(originalUrl, version, cardNumber).trim();
            String body = "";
            Pattern dataPattern = Pattern.compile("--data\\s+\"\\s*(\\{[\\s\\S]*?\\})\\s*\"", Pattern.MULTILINE);
            Matcher dataMatcher = dataPattern.matcher(content);
            if (dataMatcher.find()) {
                body = dataMatcher.group(1);
            } else {
                dataPattern = Pattern.compile("--data\\s+\"\\s*(\\{[\\s\\S]*?\\})\\s*\"", Pattern.MULTILINE);
                dataMatcher = dataPattern.matcher(content);
                if (dataMatcher.find()) {
                    body = dataMatcher.group(1);
                }
            }
            body = replacePlaceholders(body, version, cardNumber);

            String authHeader = findMatch(content, "Authorization:\\s+([^\\\\\\n]+)");
            authHeader = (authHeader != null) ? authHeader.trim().replace("'", "") : "";

            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Authorization", authHeader);
            headers.put("Content-Type", "application/json");

            String requestFileName = file.getName().replace(".curl","_request.json");
            saveRequestToFile(url, headers, body, requestDir, requestFileName);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Authorization", authHeader)
                    .header("Content-Type", "application/json")
                    .PUT(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<String> response = client.send(request,HttpResponse.BodyHandlers.ofString());
            String outputFileName = file.getName().replace(".curl", ".json");
            Path outputFile = outputDir.resolve(outputFileName);
            Files.writeString(outputFile, response.body());
            formatJsonFile(outputFile);

            System.out.println("Processed: " + file.getName());

        } catch (Exception e) {
            System.out.println("Error processing " + file.getName() + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void saveRequestToFile(String url, Map<String, String> headers,String body, Path requestDir, String fileName) throws IOException {
//        Map<String, Object> requestData = new LinkedHashMap<>();
//        requestData.put("url", url);
//        requestData.put("method","PUT");
//        requestData.put("headers", headers);
//
//        if (body != null && !body.isBlank()) {
//            try {
                Object bodyJson = mapper.readValue(body, Object.class);
//                requestData.put("payload", bodyJson);
//            } catch (Exception e) {
//                requestData.put("payload", body);
//            }
//        }
        String formattedRequest = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(bodyJson);
        Path requestFile = requestDir.resolve(fileName);
        Files.writeString(requestFile,formattedRequest);
    }

    private static String findMatch(String text, String regex) {
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(text);
        return matcher.find() ? matcher.group(1) : null;
    }

    public static void main( String[] args ) throws IOException {
        try (Scanner scanner = new Scanner(System.in)) {
            Path inputDir = Paths.get("json_curl");
            Path outputDir = Paths.get("json_output");
            Path requestDir = Paths.get("json_request");

            System.out.println("Enter card number: ");
            String cardNumber = scanner.nextLine();

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
