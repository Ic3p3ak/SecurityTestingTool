package com.soprasteria.accesscontrol.securitytestingtool;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Locale;
import java.util.Scanner;
import java.util.logging.Level;
import java.io.FileReader;
import java.util.Properties;

public class SQLInjectionManager {

    public ArrayList<String> filePaths = new ArrayList<>();
    String command;
    public File fullSQLResult = null;
    File[] sqlResults;
    public PrintWriter fullWriter;
    private ArrayList<String> resultKeywords = new ArrayList<>();
    ArrayList<String> lastRequest = new ArrayList<>();

    public SQLInjectionManager() {
        resultKeywords.add("[*]");
        resultKeywords.add(new String("critical"));
        resultKeywords.add("warning");
        resultKeywords.add("parameter:");
        resultKeywords.add("type:");
        resultKeywords.add("title:");
        resultKeywords.add("payload:");
        resultKeywords.add("operating system:");
        resultKeywords.add("application technology:");
        resultKeywords.add("back-end DBMS:");
        resultKeywords.add("test shows that");
        sqlResults = new File[2];
        sqlResults[0] = new File(SecurityTestingTool.mainDir + "/logs/sqlResult_GET.txt");
        sqlResults[1] = new File(SecurityTestingTool.mainDir + "/logs/sqlResult_POST.txt");
    }

    public String[] createCommands(String method) throws FileNotFoundException {

        if (method.equals("get")) {
            command = new String();
            int headerCount = 0;
            try (FileReader fileReader = new FileReader("configSQLInjection");) {
                Properties properties = new Properties();
                properties.load(fileReader);
                if (properties.getProperty("amountOfHeaders").matches("[+-]?\\d*(\\.\\d+)?")) {
                    headerCount = Integer.parseInt(properties.getProperty("amountOfHeaders"));
                }

                command = SecurityTestingTool.mainDir + properties.getProperty("sqlmapPath") + " --ignore-stdin --batch ";
                if (headerCount > 0) {
                    for (int i = 0; i < headerCount; i++) {
                        command += "-H " + properties.getProperty("header" + i) + " ";
                    }
                }
                command += "-u \"" + properties.getProperty("GETtarget") + "\"";
            } catch (IOException e) {
                e.printStackTrace();
            }
            return new String[]{"cmd", "/c", "python " + command};
        }
        else if (method.equals("post")){
            command = new String();
            int headerCount = 0;
            int attributeCount = 0;
            try (FileReader fileReader = new FileReader("configSQLInjection");) {
                Properties properties = new Properties();
                properties.load(fileReader);
                if (properties.getProperty("amountOfHeaders").matches("[+-]?\\d*(\\.\\d+)?")) {
                    headerCount = Integer.parseInt(properties.getProperty("amountOfHeaders"));
                }
                if (properties.getProperty("ammountOfAttributes").matches("[+-]?\\d*(\\.\\d+)?")) {
                    attributeCount = Integer.parseInt(properties.getProperty("ammountOfAttributes"));
                }
                command = SecurityTestingTool .mainDir + properties.getProperty("sqlmapPath") + " --ignore-stdin --batch ";
                if (headerCount > 0) {
                    for (int i = 0; i < headerCount; i++) {
                        command += "-H " + properties.getProperty("header" + i) + " ";
                    }
                }
                command += "-u \"" + properties.getProperty("POSTtarget") + "\" " + "--data=\"";
                for (int i = 1; i <= attributeCount; i++) {
                    if (i < attributeCount) {
                        command += properties.getProperty("attribute"+i) + "&";
                    } else {
                        command += properties.getProperty("attribute"+i) + "\" --method POST";
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            return new String[]{"cmd", "/c", "python " + command};
        }
        return null;
    }

    public void writeSQLInjectionResult(String[] commands, String method) throws IOException {

        String line = "";
        lastRequest.clear();
        ProcessBuilder pb = new ProcessBuilder(commands);
        for (String s: commands
             ) {
            SecurityTestingTool.l.log(Level.INFO,s);
        }
        SecurityTestingTool.l.log(Level.INFO,"Process starts.");
        Process sqlInjection = pb.start();
        BufferedReader reader = new BufferedReader(new InputStreamReader(sqlInjection.getInputStream()));
        SecurityTestingTool.l.log(Level.INFO,"Writing results to fullResults.txt File.");
        while ((line = reader.readLine()) != null) {
            fullWriter.println(line);
            lastRequest.add(line);
        }

        SecurityTestingTool.l.log(Level.INFO,"Process ends.");
        if (method.equals("get")){
            writeShortResult(0);
        }
        else {
            writeShortResult(1);
        }
        SecurityTestingTool.l.log(Level.INFO,"Finished writing.");
        reader.close();

    }

    private void writeShortResult(int i) throws IOException{
        PrintWriter writer = new PrintWriter(new FileWriter(sqlResults[i]),true);
        SecurityTestingTool.l.log(Level.INFO,"Writing to sqlResult.txt.");
        for (String l: lastRequest) {
            if (!l.equals("")) {
                for (String keyword: resultKeywords
                ){
                    if (l.toLowerCase().contains(keyword)) {
                        writer.println(l);
                        if (keyword == "payload:"){
                            writer.println("");
                        }
                    }
                }
            }
        }
        writer.close();
    }
}
