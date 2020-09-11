package dev.lab1;

import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.ListIterator;
import java.util.function.Function;

public class Lab1 {
    private static final String source = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final String target = "Q5A8ZWS0XEDC6RFVT9GBY4HNU3J2MI1KO7LPabcdefghijklmnopqrstuvwxyz";

    public static String obfuscate(String s) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int index = source.indexOf(c);
            result.append(index > -1 ? target.charAt(index) : c);
        }
        return result.toString();
    }

    public static String unobfuscate(String s) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int index = target.indexOf(c);
            result.append(index > -1 ? source.charAt(index) : c);
        }
        return new String(result);
    }

    public static void printOutHelp() {
        System.out.println("Usage: <MODE> INPUT_FILE_PATH OUTPUT_FILE_PATH");
        System.out.println("MODES:");
        System.out.println("       obfuscate");
        System.out.println("       unobfuscate");
    }

    public static void printDocument(Document doc, OutputStream out) throws IOException, TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        transformer.setOutputProperty(OutputKeys.METHOD, "xml");
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");

        transformer.transform(new DOMSource(doc), new StreamResult(new OutputStreamWriter(out, StandardCharsets.UTF_8)));
    }

    public static void main(String[] args) {
        InputStream input;
        String outputPath;
        boolean obfuscateMode;
        if (args.length < 3 || args[0].equals("help")) {
            printOutHelp();
            return;
        } else {
            if (args[0].equals("obfuscate")) {
                obfuscateMode = true;
            } else if (args[0].equals("unobfuscate")) {
                obfuscateMode = false;
            } else {
                printOutHelp();
                return;
            }
            try {
                input = new FileInputStream(args[1]);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
                return;
            }
            outputPath = args[2];
        }
        try {
            DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            Document document = documentBuilder.parse(input);

            applyTransformerToDocument(document, obfuscateMode ? Lab1::obfuscate : Lab1::unobfuscate);
            FileOutputStream outputStream = new FileOutputStream(outputPath);
            printDocument(document, outputStream);
        } catch (ParserConfigurationException | SAXException | IOException | TransformerException ex) {
            ex.printStackTrace(System.out);
        }
    }

    private static void applyTransformerToDocument(Document document, Function<String, String> transformer) {
        Node root = document.getDocumentElement();

        ArrayList<Node> nodesToTraverse = new ArrayList<>();
        nodesToTraverse.add(root);
        ListIterator<Node> iterator = nodesToTraverse.listIterator();

        while (iterator.hasNext()) {
            Node node = iterator.next();
            if (node.getNodeType() == Node.TEXT_NODE) {
                String nodeValue = node.getNodeValue();
                String obfuscatedValue = transformer.apply(nodeValue);
                node.setNodeValue(obfuscatedValue);
            }
            if (node.hasAttributes()) {
                NamedNodeMap nodeAttributes = node.getAttributes();
                for (int i = 0; i < nodeAttributes.getLength(); i++) {
                    Node item = nodeAttributes.item(i);
                    iterator.add(item);
                    iterator.previous();
                }
            }
            if (node.hasChildNodes()) {
                NodeList childNodes = node.getChildNodes();
                for (int i = 0; i < childNodes.getLength(); i++) {
                    Node item = childNodes.item(i);
                    iterator.add(item);
                    iterator.previous();
                }
            }
        }
    }
}
