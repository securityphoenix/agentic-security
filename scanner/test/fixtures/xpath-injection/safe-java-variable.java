import javax.xml.xpath.*;
public class XPathLookup {
  public static String find(XPath xpath, Document doc, String name) throws Exception {
    // Safe: parameterized via XPathVariableResolver.
    xpath.setXPathVariableResolver(v -> "name".equals(v.getLocalPart()) ? name : null);
    XPathExpression expr = xpath.compile("/users/user[name=$name]/email");
    return (String) expr.evaluate(doc, XPathConstants.STRING);
  }
}
