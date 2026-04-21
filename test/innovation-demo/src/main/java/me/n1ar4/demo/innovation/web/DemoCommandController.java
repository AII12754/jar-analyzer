package me.n1ar4.demo.innovation.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/demo")
public class DemoCommandController {
    private final DemoCommandFacade demoCommandFacade;

    public DemoCommandController(DemoCommandFacade demoCommandFacade) {
        this.demoCommandFacade = demoCommandFacade;
    }

    @GetMapping("/exec")
    public Map<String, String> exec(@RequestParam String cmd) {
        demoCommandFacade.dispatch(cmd);
        Map<String, String> result = new LinkedHashMap<>();
        result.put("status", "accepted");
        result.put("cmd", cmd);
        return result;
    }
}