package me.n1ar4.demo.innovation.serialization;

import java.io.IOException;
import java.io.ObjectInputStream;

public class ExecPayload extends BaseSerializablePayload implements Comparable<ExecPayload> {
    private String profile = "demo";

    private void readObject(ObjectInputStream inputStream) throws IOException, ClassNotFoundException {
        inputStream.defaultReadObject();
        triggerSink(command);
    }

    private Object readResolve() {
        triggerSink(command);
        return this;
    }

    @Override
    public int compareTo(ExecPayload other) {
        triggerSink(command);
        return this.profile.compareTo(other.profile);
    }

    @Override
    public int hashCode() {
        triggerSink(command);
        return profile.hashCode();
    }

    @Override
    public String toString() {
        triggerSink(command);
        return "ExecPayload{" + profile + "}";
    }
}