package org.example;
import java.io.IOException;
import java.net.http.HttpClient;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.net.ssl.SSLContext;

public class JSONExecutor {
    private static final ObjectMapper mapper = new ObjectMapper();

    public static void main( String[] args ) {
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

            }
        }


    }

    private static SSLContext createInsecureSslContext() {
    }
}
