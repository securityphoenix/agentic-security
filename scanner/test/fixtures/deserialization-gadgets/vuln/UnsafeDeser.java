import java.io.*;
import javax.servlet.http.*;
public class UnsafeDeser {
  public Object handle(HttpServletRequest request) throws Exception {
    InputStream in = request.getInputStream();  // tainted source
    ObjectInputStream ois = new ObjectInputStream(in);
    return ois.readObject();  // Unsafe sink — tainted-fed.
  }
}
