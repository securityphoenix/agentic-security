import javax.xml.xpath.*;
public class XPathLookup {
  public static String find(XPath xpath, Document doc, String name) throws Exception {
    XPathExpression expr = xpath.compile("/users/user[name='" + name + "']/email");  // Vuln
    return (String) expr.evaluate(doc, XPathConstants.STRING);
  }
}
