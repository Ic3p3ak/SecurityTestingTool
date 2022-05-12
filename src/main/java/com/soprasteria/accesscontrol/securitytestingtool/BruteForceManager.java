package com.soprasteria.accesscontrol.securitytestingtool;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.logging.Level;
import java.io.FileReader;
import java.util.Properties;

public class BruteForceManager {
    Properties properties = new Properties();
    File output;
    String parameterUsername;
    String parameterPW;

    public String[] BuildHydraCommand() throws FileNotFoundException {

        //File bruteInfoFile = new File(infoPath);
        int attributeCount = 0;
        String command = new String();
        try(FileReader fileReader = new FileReader("configBruteForce")){
            properties.load(fileReader);
            try(FileWriter clear = new FileWriter(properties.getProperty("outputPath"))){
                clear.write("");
                clear.close();
            }
            if(properties.getProperty("numberOfBodyAttributes").matches("[+-]?\\d*(\\.\\d+)?")) {
                attributeCount = Integer.parseInt(properties.getProperty("numberOfBodyAttributes"));
            }
            command = SecurityTestingTool.mainDir + properties.getProperty("hydraPath") + " -v -V -o " + SecurityTestingTool.mainDir + properties.getProperty("outputPath");
            if (properties.getProperty("useUsernameList").equals("true")){
                parameterUsername = " -L " + properties.getProperty("usernameList");
            }
            else
            {
                parameterUsername = " -l " + properties.getProperty("username");
            }
            if (properties.getProperty("usePasswordList").equals("true")){
                parameterPW = " -P " + SecurityTestingTool.mainDir + properties.getProperty("passwordList");
            }
            else
            {
                parameterPW = " -p " + properties.getProperty("password");
            }
            command += parameterUsername + parameterPW + " " + properties.getProperty("targetIP") + " http-post-form \"" + properties.getProperty("targetPath") + ":";
            for (int j = 1; j<=attributeCount;j++) {
                if(j<attributeCount) {
                    command += properties.getProperty(Integer.toString(j)) + "&";
                }
                else{
                    command += properties.getProperty(Integer.toString(j)) + ":";
                }
            }
            command += properties.getProperty("errorMessage") + "\"";

        } catch (IOException e) {
            e.printStackTrace();
        }


        return new String[]{"cmd", "/c", command};
    }

    public void simulateBruteForceAttack(String[] commands) throws IOException, InterruptedException {

        output = new File(properties.getProperty("outputPath"));
        ProcessBuilder pb = new ProcessBuilder(commands);
        for (String s: commands
        ) {
            SecurityTestingTool.l.log(Level.INFO,s);
        }
        SecurityTestingTool.l.log(Level.INFO,"Process starts.");
        Process sqlInjection = pb.start();

        // Read output from Hydra process...
        BufferedReader in = new BufferedReader(new InputStreamReader(sqlInjection.getInputStream()));
        String line;
        while ((line = in.readLine()) != null) {
            System.out.println(line);
        }
        sqlInjection.waitFor();
        System.out.println("ok!");
        in.close();
    }
}
