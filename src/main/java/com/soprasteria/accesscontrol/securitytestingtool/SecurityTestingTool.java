package com.soprasteria.accesscontrol.securitytestingtool;

import java.io.*;

import java.awt.*;
import java.io.Console;
import java.io.IOException;
import java.util.ArrayList;
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
    public FileHandler fh = new FileHandler("/logs/securityTestingLog.log",500000,2,true);
    SimpleFormatter sf = new SimpleFormatter();

    //Constructor:
    public SecurityTestingTool() throws IOException{

        sqlInjectionManager = new SQLInjectionManager();
        l.setLevel(Level.INFO);
        fh.setFormatter(sf);
        fh.setLevel(Level.INFO);
        l.addHandler(fh);
        l.log(Level.INFO,"Logger created");
        logFolder.mkdir();
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

    public static void main(String[] args) throws IOException {

        securityTestingTool = new SecurityTestingTool();
        Console console = System.console();
        if(console == null && !GraphicsEnvironment.isHeadless()){

            sqlInjectionManager.getUserInput();

            for (int i = 0;i<sqlInjectionManager.filePaths.size();i++) {
                String filePath = sqlInjectionManager.filePaths.get(i);
                String[] commands = sqlInjectionManager.createCommands(filePath);

                for (String c : commands) {
                    l.log(Level.INFO, c);
                }

                sqlInjectionManager.writeSQLInjectionResult(commands,i);
            }
            sqlInjectionManager.fullWriter.close();
            securityTestingTool.fh.close();

        }else{
            SecurityTestingTool.main(new String[0]);
            System.out.println("Program has ended, please type 'exit' to close the console");
        }
        //Runtime.getRuntime().exec("cmd /c python C:/Users/mbrochhaus/OneDrive/Bachelor/sqlmap/sqlmapproject-sqlmap-1.6.4-2-gd5fb92e/sqlmapproject-sqlmap-d5fb92e/sqlmap.py");
    }
}
