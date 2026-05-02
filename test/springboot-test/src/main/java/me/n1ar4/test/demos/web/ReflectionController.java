package me.n1ar4.test.demos.web;

import org.springframework.web.bind.annotation.*;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 * 反射调用演示控制器
 * 用于演示 jar-analyzer 表达式搜索功能：
 *   containsInvoke("java.lang.reflect.Method","invoke")
 *   excludeInvoke("java.lang.System","exit")
 */
@RestController
@RequestMapping("/reflect")
public class ReflectionController {

    /**
     * 纯反射调用 - 不含 System.exit
     * 演示 2 和 演示 3 均能搜索到该方法
     */
    @GetMapping("/run")
    public Map<String, Object> reflectRun(@RequestParam String input) {
        Map<String, Object> result = new HashMap<>();
        try {
            Class<?> clazz = Class.forName("java.lang.StringBuilder");
            Object instance = clazz.getDeclaredConstructor().newInstance();
            Method appendMethod = clazz.getMethod("append", String.class);
            Object ret = appendMethod.invoke(instance, input);
            result.put("status", "ok");
            result.put("result", ret.toString());
        } catch (Exception e) {
            result.put("error", e.getMessage());
        }
        return result;
    }

    /**
     * 使用了反射，同时调用了 System.exit
     * 演示 2 能搜索到，演示 3（加 excludeInvoke）会被过滤掉
     */
    @GetMapping("/exit-or-run")
    public String reflectOrExit(@RequestParam String input, @RequestParam boolean doExit) {
        try {
            Class<?> clazz = Class.forName("java.lang.StringBuilder");
            Object instance = clazz.getDeclaredConstructor().newInstance();
            Method method = clazz.getMethod("append", String.class);
            method.invoke(instance, input);
            if (doExit) {
                System.exit(0);
            }
        } catch (Exception e) {
            System.exit(1);
        }
        return "ok";
    }

    /**
     * 另一个纯反射调用示例
     * 演示 2 和 演示 3 均能搜索到该方法
     */
    @GetMapping("/invoke-only")
    public String reflectOnly(@RequestParam String className,
                               @RequestParam String methodName) {
        try {
            Class<?> clazz = Class.forName(className);
            Object instance = clazz.getDeclaredConstructor().newInstance();
            Method method = clazz.getDeclaredMethod(methodName);
            method.setAccessible(true);
            method.invoke(instance);
        } catch (Exception e) {
            return "error: " + e.getMessage();
        }
        return "done";
    }
}
