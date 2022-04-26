package com.soprasteria.accesscontrol.securitytestingtool;

import java.io.*;
import java.util.ArrayList;
import java.util.Locale;
import java.util.Scanner;
import java.util.logging.Level;

public class SQLInjectionManager {

    Scanner scanner = new Scanner(System.in);
    int numberOfFiles = 0;
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
    }

    public void getUserInput(){

        System.out.println("How many different Injections do you want to make? :\n");
        String textNumberOfFiles = scanner.next();
        SecurityTestingTool.l.log(Level.INFO,textNumberOfFiles + " different Files.");
        while(!textNumberOfFiles.matches("[+-]?\\d*(\\.\\d+)?")){
            System.out.println("How many different Injections do you want to make? :\n");
            textNumberOfFiles = scanner.next();
            SecurityTestingTool.l.log(Level.INFO,textNumberOfFiles + " different Files.");
        }
        numberOfFiles = Integer.parseInt(textNumberOfFiles);
        sqlResults = new File[numberOfFiles];
        for (int i = 0; i< sqlResults.length; i++){
            sqlResults[i] = new File(SecurityTestingTool.resultPath + "/sqlResult_" + (i+1) + ".txt");
        }
        for (int i = 0; i<numberOfFiles;i++) {
            System.out.println("Please insert the Path where the information file number " + (1+i) + " is located: \n");
            filePaths.add(scanner.next());
        }
    }

    public String[] createCommands(String filePath) throws FileNotFoundException {

            File info = new File(filePath);
            Scanner obj = new Scanner(info);
            command = new String();
            int headerCount = 0;
            ArrayList<String> infoContent = new ArrayList<>();
            while (obj.hasNextLine()) {
                infoContent.add(obj.nextLine());
                SecurityTestingTool.l.log(Level.INFO, infoContent.get(infoContent.size() - 1));
            }
            if (infoContent.get(1).matches("[+-]?\\d*(\\.\\d+)?")) {
                headerCount = Integer.parseInt(infoContent.get(1));
                infoContent.remove(infoContent.get(1));
            }
            for (int i = 0; i < infoContent.size(); i++) {
                if (i == 0) {
                    command = infoContent.get(i) + " --ignore-stdin --batch ";
                } else if (i >= 1 && i <= headerCount) {
                    command += "-H " + infoContent.get(i) + " ";
                } else if (i == headerCount + 1) {
                    command += "-u \"" + infoContent.get(i) + "\" ";
                } else if (i > headerCount + 1) {
                    if (i == headerCount + 2) {
                        command += "--data=\"";
                    }
                    if (i < infoContent.size() - 1) {
                        command += infoContent.get(i) + "&";
                    } else {
                        command += infoContent.get(i) + "\"";
                    }
                }
            }
            return new String[]{"cmd", "/c", "python " + command};
    }

    public void writeSQLInjectionResult(String[] commands, int i) throws IOException {

        String line = "";

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
        writeShortResult(i);
        SecurityTestingTool.l.log(Level.INFO,"Finished writing.");


    }

    private void writeShortResult(int i) throws IOException{
        PrintWriter writer = new PrintWriter(new FileWriter(sqlResults[i]),true);
        BufferedReader fileReader = new BufferedReader(new FileReader(fullSQLResult));
        ArrayList<String> resultLines = new ArrayList();
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
