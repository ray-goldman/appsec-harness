import javax.xml.parsers.*;
import org.w3c.dom.Document;
import java.io.InputStream;

public class Parser {
    public Document parse(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        return dbf.newDocumentBuilder().parse(in);
    }
}
