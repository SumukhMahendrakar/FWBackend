package com.rvitm.FWBackend.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    public static class XssRequest {
        private String link;
        private String depth;
        private String method;

        public String getLink() {
            return link;
        }

        public void setLink(String url) {
            this.link = url;
        }

        public String getDepth() { return depth; }

        public void setDepth(String depth) { this.depth = depth; }

        public String getMethod() {
            return method;
        }

        public void setMethod(String method) {
            this.method = method;
        }
    }

    public static class SqlMapRequest {
        private String link;
        private String database;
        private String table;
        public String getLink() { return link; }
        public void setLink(String url) { this.link = url; }
        public String getDatabase() { return database; }
        public void setDatabase(String database) { this.database = database; }
        public String getTable() { return table; }
        public void setTable(String table) { this.table = table; }
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

    @PostMapping(value = "/headers/information")
    @CrossOrigin(origins = "http://localhost:3000")
    private static String infoHeaders(@RequestBody UrlRequest urlRequest) {
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

    @PostMapping(value = "/headers/cache")
    @CrossOrigin(origins = "http://localhost:3000")
    private static String cacheHeaders(@RequestBody UrlRequest urlRequest) {
        try{
            String url = urlRequest.getLink();
            System.out.println("Received URL: " + url);
            String cmd = "python D:\\FW-Project\\Header\\shcheck.py " +url+" -x";
            System.out.println(cmd);
            Process process = Runtime.getRuntime().exec("python D:\\FW-Project\\Header\\shcheck.py "+url+" -x -j");
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

    @PostMapping(value = "/headers/ssl")
    @CrossOrigin(origins = "http://localhost:3000")
    private static String skipSLSHeaders(@RequestBody UrlRequest urlRequest) {
        try{
            String url = urlRequest.getLink();
            System.out.println("Received URL: " + url);
            String cmd = "python D:\\FW-Project\\Header\\shcheck.py " +url+" -d -i -x -j";
            System.out.println(cmd);
            Process process = Runtime.getRuntime().exec("python D:\\FW-Project\\Header\\shcheck.py "+url+" -d -i -x -j");
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


    @PostMapping(value = "/xss")
    @CrossOrigin(origins = "http://localhost:3000")
    private static String xssMethod(@RequestBody XssRequest xssRequest) {
        try{
            String url = xssRequest.getLink();
            System.out.println("Received URL: " + url);
            List<String> command = new ArrayList<>();
            command.add("python");
            command.add("D:\\FW-Project\\Network-Fortification\\PwnXSS\\PwnXSS\\pwnxss.py");
            command.add("-u");
            command.add(url);
            if(!(xssRequest.getDepth().equals(""))){
                command.add("--depth");
                command.add(xssRequest.getDepth());
            }
            if(!(xssRequest.getMethod().equals(""))){
                command.add("--method");
                command.add(xssRequest.getMethod());
            }
            System.out.println(command);
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            Process process = processBuilder.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            int i=0;
            while ((line = reader.readLine()) != null && i!=100) {
                String line1 =  line.replaceAll("\\[\\S*\\]", "").replaceAll("\u001B\\[[0-9;]*m","").trim();
                output.append(line1).append("\n");
                i=i+1;
            }
            return output.toString();
        } catch (Exception e) {
            return "Error executing command: " + e.getMessage();
        }
    }

    @PostMapping(value = "/sql/batch")
    @CrossOrigin(origins = "http://localhost:3000")
    private static String sqlBatch(@RequestBody SqlMapRequest sqlMapRequest) {
        try{
            String url = sqlMapRequest.getLink();
            System.out.println("Received URL: " + url);
            List<String> command = new ArrayList<>();
            command.add("python");
            command.add("D:\\FW-Project\\Network-Fortification\\sqlmap-master\\sqlmap.py");
            command.add("-u");
            command.add(url);
            command.add("--batch");
            System.out.println(command);
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            Process process = processBuilder.start();
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

    @PostMapping(value = "/sql/getDatabases")
    @CrossOrigin(origins = "http://localhost:3000")
    private static String sqlDatabases(@RequestBody SqlMapRequest sqlMapRequest) {
        try{
            String url = sqlMapRequest.getLink();
            System.out.println("Received URL: " + url);
            List<String> command = new ArrayList<>();
            command.add("python");
            command.add("D:\\FW-Project\\Network-Fortification\\sqlmap-master\\sqlmap.py");
            command.add("-u");
            command.add(url);
            command.add("--batch");
            command.add("--dbs");
            System.out.println(command);
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            Process process = processBuilder.start();
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

    @PostMapping(value = "/sql/getTables")
    @CrossOrigin(origins = "http://localhost:3000")
    private static String sqlTables(@RequestBody SqlMapRequest sqlRequest) {
        try{
            String url = sqlRequest.getLink();
            System.out.println("database is");
            System.out.println("Received URL: " + url);
            List<String> command = new ArrayList<>();
            command.add("python");
            command.add("D:\\FW-Project\\Network-Fortification\\sqlmap-master\\sqlmap.py");
            command.add("-u");
            command.add(url);
            command.add("--batch");
            command.add("-D");
            command.add(sqlRequest.getDatabase());
            command.add("--tables");
            System.out.println(command);
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            Process process = processBuilder.start();
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

    @PostMapping(value = "/sql/getColumns")
    @CrossOrigin(origins = "http://localhost:3000")
    private static String sqlTableColumns(@RequestBody SqlMapRequest sqlRequest) {
        try{
            String url = sqlRequest.getLink();
            System.out.println("database is");
            System.out.println("Received URL: " + url);
            List<String> command = new ArrayList<>();
            command.add("python");
            command.add("D:\\FW-Project\\Network-Fortification\\sqlmap-master\\sqlmap.py");
            command.add("-u");
            command.add(url);
            command.add("--batch");
            command.add("-D");
            command.add(sqlRequest.getDatabase());
            command.add("-T");
            command.add(sqlRequest.getTable());
            command.add("--columns");
            System.out.println(command);
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            Process process = processBuilder.start();
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

    @PostMapping(value = "/sql/getData")
    @CrossOrigin(origins = "http://localhost:3000")
    private static String sqlTablesData(@RequestBody SqlMapRequest sqlRequest) {
        try{
            String url = sqlRequest.getLink();
            System.out.println("database is");
            System.out.println("Received URL: " + url);
            List<String> command = new ArrayList<>();
            command.add("python");
            command.add("D:\\FW-Project\\Network-Fortification\\sqlmap-master\\sqlmap.py");
            command.add("-u");
            command.add(url);
            command.add("--batch");
            command.add("-D");
            command.add(sqlRequest.getDatabase());
            command.add("-T");
            command.add(sqlRequest.getTable());
            command.add("--dump");
            System.out.println(command);
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            Process process = processBuilder.start();
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
