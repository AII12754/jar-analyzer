package me.n1ar4.demo.innovation.serialization;

import java.io.Serializable;

public abstract class BaseSerializablePayload implements Serializable {
    protected String command = "calc";

    protected void triggerSink(String value) {
        new SerializableCommandBridge().stageOne(value);
    }
}