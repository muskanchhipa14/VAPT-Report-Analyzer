package com.example.vulnerable;

import java.io.*;
import java.sql.*;
import java.security.MessageDigest;
import javax.xml.parsers.DocumentBuilderFactory;

public class VulnerableService {

    // 1. Hardcoded Credential (CWE-798)
    private static final String apiKey = "sec_key_abcdef9876543210zyx";

    // 2. SQL Injection (CWE-89)
    public void getUserData(Connection conn, String userId) throws SQLException {
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
        ResultSet rs = stmt.executeQuery(sql);
    }

    // 3. Command Injection (CWE-78)
    public void pingHost(String host) throws IOException {
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    // 4. XXE Injection (CWE-611)
    public void parseXml(InputStream is) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.newDocumentBuilder().parse(is);
    }

    // 5. Path Traversal (CWE-22)
    public FileInputStream getFile(String userPath) throws FileNotFoundException {
        return new FileInputStream("/var/data/" + userPath);
    }

    // 6. Insecure Deserialization (CWE-502)
    public Object deserializeObject(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    // 7. Weak Cryptography (CWE-327)
    public byte[] hashMd5(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }
}
