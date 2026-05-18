import java.io.*;
public class SafeDeser {
  public static Object load(byte[] data) {
    // Safe: no deserialization sink at all — JSON only.
    return new com.fasterxml.jackson.databind.ObjectMapper().readValue(data, MyType.class);
  }
}
