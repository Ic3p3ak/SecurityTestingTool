package com.soprasteria.accesscontrol.securitytestingtool;

import java.io.*;

import java.awt.*;
import java.io.Console;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Locale;
import java.util.Properties;
import java.util.Scanner;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class SecurityTestingTool {

    public static Logger l = Logger.getLogger(SecurityTestingTool.class.getName());
    public static String resultPath = "/logs";
    public static File logFolder = new File(resultPath);
    public static SecurityTestingTool securityTestingTool;
    public static SQLInjectionManager sqlInjectionManager;
    public static BruteForceManager bruteForceManager;
    public FileHandler fh = new FileHandler("/logs/securityTestingLog.log",500000,2,true);
    SimpleFormatter sf = new SimpleFormatter();
    Properties properties = new Properties();
    protected String reportPath;
    public File reportFile = new File(reportPath);


    //Constructor:
    public SecurityTestingTool() throws IOException{

        sqlInjectionManager = new SQLInjectionManager();
        bruteForceManager = new BruteForceManager();
        l.setLevel(Level.INFO);
        fh.setFormatter(sf);
        fh.setLevel(Level.INFO);
        l.addHandler(fh);
        l.log(Level.INFO,"Logger created");
        logFolder.mkdir();
        try(FileReader fileReader = new FileReader("configSecurityTestingTool")) {
            properties.load(fileReader);
        }
        reportPath = properties.getProperty("logPath") + "/report.txt";
        if (logFolder.exists()){
            l.log(Level.INFO,"Folder exists!");
            try {
                sqlInjectionManager.fullSQLResult = new File (resultPath + "/fullResults.txt");
                if (sqlInjectionManager.fullSQLResult.createNewFile()){

                    l.log(Level.INFO,"result file created!\n");
                }
                else {
                    l.log(Level.INFO,"result file already exists!");
                }
                sqlInjectionManager.fullWriter = new PrintWriter(new FileWriter(sqlInjectionManager.fullSQLResult,false),true);
                sqlInjectionManager.fullWriter.print("");
                sqlInjectionManager.fullWriter = new PrintWriter(new FileWriter(sqlInjectionManager.fullSQLResult,true),true);
            }
            catch (IOException e){
                l.log(Level.INFO,e.toString());
            }
        }
    }

    public static void main(String[] args) throws IOException, InterruptedException {

        ArrayList<String> resultKeywords = new ArrayList<>();
        resultKeywords.add("parameter:");
        resultKeywords.add("type:");
        resultKeywords.add("title:");
        resultKeywords.add("payload:");
        resultKeywords.add("operating system:");
        resultKeywords.add("application technology:");
        resultKeywords.add("[http-post-form]");
        securityTestingTool = new SecurityTestingTool();
        Console console = System.console();
        if(console == null && !GraphicsEnvironment.isHeadless()){

            // Start SQL-Injection simulation
            //Create the command for sqlmap
            String[] commandsSqlmap = sqlInjectionManager.createCommands("get");

            for (String c : commandsSqlmap) {
                l.log(Level.INFO, c);
            }
            // Starting the sqlmap process and create Result files.
            sqlInjectionManager.writeSQLInjectionResult(commandsSqlmap,"get");
            commandsSqlmap = sqlInjectionManager.createCommands("post");

            for (String c : commandsSqlmap) {
                l.log(Level.INFO, c);
            }
            // Starting the sqlmap process and create Result files.
            sqlInjectionManager.writeSQLInjectionResult(commandsSqlmap,"post");
            sqlInjectionManager.fullWriter.close();

            // Start with Brute Force Simulation
            // Creating the Command to run THC Hydra
            String[] commandsHydra = bruteForceManager.BuildHydraCommand();
            // Start the simulation and catch the Output of Hydra... Hydra doesn't have an Option to create proper output to a file.
            bruteForceManager.simulateBruteForceAttack(commandsHydra);
            securityTestingTool.createReport(resultKeywords);
            securityTestingTool.fh.close();


        }else{
            SecurityTestingTool.main(new String[0]);
            System.out.println("Program has ended, please type 'exit' to close the console");
        }
    }

    void createReport(ArrayList<String> resultKeywords) throws IOException {

        BufferedReader reader = new BufferedReader(new FileReader(sqlInjectionManager.fullSQLResult));
        PrintWriter printWriter = new PrintWriter(new FileWriter(securityTestingTool.reportFile),true);
        Boolean sqlSuccessful = false;
        Boolean bruteForceSuccessful = false;
        String line = "";
        String lineB="";
        System.out.println("\n\n\n\n");
        printWriter.println("------------------------------------------------------------------------------------------------------------------------------------------------------");
        printWriter.println("---------------------------------------------------------------------------");
        printWriter.println("---------------------------------------------------------------------------");
        printWriter.println("REPORT:");
        printWriter.println("SQL-INJECTION:");
        while ((lineB = reader.readLine()) != null){
            if (lineB.toLowerCase().contains("parameter:")) {
                sqlSuccessful = true;
                printWriter.println("SQL injection was successful with:");
                printWriter.println("---------------------------------------------------------------------------");
                printWriter.println("---------------------------------------------------------------------------\n");
                printWriter.println(lineB);
                break;
            }
        }
        while ((line = reader.readLine()) != null){
            if (sqlSuccessful) {
                for (String keyword : resultKeywords
                ) {
                    if (line.toLowerCase().contains(keyword)) {
                        printWriter.println(line);
                        if (keyword.equals("payload:")) {
                            printWriter.println("");
                        }
                        else if (keyword.equals("application technology:")){
                            printWriter.println("---------------------------");
                        }
                    }
                }
            }
            else{
                printWriter.println("SQL injection was not successful!\nYour System is Safe against SQL-Injections!\nGood Job!");
                printWriter.println("---------------------------------------------------------------------------");
                printWriter.println("---------------------------------------------------------------------------");
            }
        }
        printWriter.println("");
        printWriter.println("---------------------------------------------------------------------------");
        printWriter.println("---------------------------------------------------------------------------");
        printWriter.println("BRUTE FORCE:");
        line = "";
        lineB="";
        reader.close();
        reader = new BufferedReader(new FileReader(bruteForceManager.properties.getProperty("outputPath")));
        while ((lineB = reader.readLine()) != null){
            if (lineB.toLowerCase().contains("[http-post-form]")){
                bruteForceSuccessful = true;
                printWriter.println("Brute Force Attack was successful with:");
                printWriter.println("---------------------------------------------------------------------------");
                printWriter.println("---------------------------------------------------------------------------\n");
                printWriter.println(lineB);
                break;
            }
        }
        while ((line = reader.readLine()) != null){
            if (bruteForceSuccessful) {
                for (String keyword : resultKeywords
                ) {
                    if (line.toLowerCase().contains(keyword)) {
                        printWriter.println("---------------------------");
                        printWriter.println(line);
                    }
                }
            }
            else {
                printWriter.println("Brute Force Attack was not successful!\nYour System is Safe against Brute Force!\nGood Job!!!");
                printWriter.println("---------------------------------------------------------------------------");
                printWriter.println("---------------------------------------------------------------------------");
            }
        }
        printWriter.println("");
        printWriter.println("---------------------------------------------------------------------------");
        printWriter.println("---------------------------------------------------------------------------");
        printWriter.println("This Report can be found at: " + securityTestingTool.reportPath);
        printWriter.println("---------------------------------------------------------------------------");
        printWriter.println("---------------------------------------------------------------------------\n");
        printWriter.println("------------------------------------------------------------------------------------------------------------------------------------------------------");
        reader.close();
        reader = new BufferedReader(new FileReader(securityTestingTool.reportFile));
        while ((line = reader.readLine()) != null){
            System.out.println(line);
        }
        reader.close();
        printWriter.close();
    }
}
