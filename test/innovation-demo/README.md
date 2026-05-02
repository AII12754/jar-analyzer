innovation-demo 用于同时演示 jar-analyzer 的两个新增能力：

1. A：反序列化利用链自动挖掘
2. B：过程间数据流分析（Spring MVC Web Source -> Runtime.exec）

构建方式：

```bash
cd test/innovation-demo
mvn clean package -DskipTests
```

生成 JAR：

`target/innovation-demo-0.0.1-SNAPSHOT.jar`