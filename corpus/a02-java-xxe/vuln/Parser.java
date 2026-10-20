import javax.xml.parsers.*;
import org.w3c.dom.Document;
import java.io.InputStream;

public class Parser {
    public Document parse(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        return dbf.newDocumentBuilder().parse(in);
    }
}
