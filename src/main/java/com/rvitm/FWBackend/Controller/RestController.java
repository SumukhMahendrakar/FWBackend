package com.rvitm.FWBackend.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URLDecoder;

@org.springframework.web.bind.annotation.RestController
public class RestController {

    public static class UrlRequest {
        private String link;

        public String getLink() {
            return link;
        }

        public void setLink(String url) {
            this.link = url;
        }
    }
    @GetMapping(value = "/mlScript")
    private static String runMlScript() {
        try {
            // Execute the terminal command
            Process process = Runtime.getRuntime().exec("python D:\\FW-Project\\WebAppFirewall-with-ML\\gui.py");

            int exitCode = process.waitFor();
            return "Command executed with exit code : "+exitCode;
        } catch (Exception e) {
            return "Error executing command: " + e.getMessage();
        }
    }

    @PostMapping(value = "/headers")
    @CrossOrigin(origins = "http://localhost:3000")
    private static String Headers(@RequestBody UrlRequest urlRequest) {
        try{
            String url = urlRequest.getLink();
            System.out.println("Received URL: " + url);
            String cmd = "python D:\\FW-Project\\Header\\shcheck.py " +url+" -i";
            System.out.println(cmd);
            Process process = Runtime.getRuntime().exec("python D:\\FW-Project\\Header\\shcheck.py "+url+" -i -j");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return output.toString();
        } catch (Exception e) {
            return "Error executing command: " + e.getMessage();
        }
    }
}
