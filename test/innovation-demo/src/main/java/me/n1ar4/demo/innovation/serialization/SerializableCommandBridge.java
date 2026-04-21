package me.n1ar4.demo.innovation.serialization;

import me.n1ar4.demo.innovation.exec.CommandExecSupport;

public class SerializableCommandBridge {
    public void stageOne(String command) {
        stageTwo(command);
    }

    public void stageTwo(String command) {
        CommandExecSupport.exec(command);
    }
}