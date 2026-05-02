package me.n1ar4.demo.innovation.web;

import me.n1ar4.demo.innovation.exec.CommandExecSupport;
import org.springframework.stereotype.Service;

@Service
public class DemoCommandService {
    public void execute(String command) {
        doInternal(command);
    }

    private void doInternal(String command) {
        CommandExecSupport.exec(command);
    }
}