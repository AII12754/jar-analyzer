package me.n1ar4.demo.innovation.web;

import org.springframework.stereotype.Component;

@Component
public class DemoCommandFacade {
    private final DemoCommandService demoCommandService;

    public DemoCommandFacade(DemoCommandService demoCommandService) {
        this.demoCommandService = demoCommandService;
    }

    public void dispatch(String command) {
        String forwarded = forward(command);
        demoCommandService.execute(forwarded);
    }

    public String forward(String command) {
        return command;
    }
}