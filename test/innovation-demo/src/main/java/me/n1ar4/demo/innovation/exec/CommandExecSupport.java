package me.n1ar4.demo.innovation.exec;

import java.io.IOException;

public final class CommandExecSupport {
    private CommandExecSupport() {
    }

    public static void exec(String command) {
        try {
            Runtime.getRuntime().exec(command);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}