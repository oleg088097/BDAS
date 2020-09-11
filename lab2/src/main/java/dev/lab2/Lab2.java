package dev.lab2;


import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.function.Function;

@SuppressWarnings("unchecked")
public class Lab2 {
    private final Map<String, Function<String[], Boolean>> operations = new HashMap<>();
    Lab2() {
        operations.put("encrypt", this::encrypt);
        operations.put("decrypt", this::decrypt);
        operations.put("sign", this::sign);
        operations.put("verify", this::verify);
    }

    private boolean encrypt(String[] args) {
        if (args.length < 3) {
            return false;
        }
        X509Certificate x509Certificate;
        try {
            x509Certificate = loadPublicCert(args[0]);
        } catch (CertificateException | NoSuchProviderException | FileNotFoundException e) {
            System.out.println("Provided PUBLIC_CERT_PATH file "+ args[0] +" does not contain valid X509 Certificate");
            return false;
        }

        byte[] data = getInputBytes(args[1]);
        if (data == null) return false;

        try {
            new FileOutputStream(args[2]).write(encryptData(data, x509Certificate));
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    private boolean decrypt(String[] args) {
        if (args.length < 3) {
            return false;
        }
        PrivateKey privateKey;
        try {
            privateKey = loadPrivateKey(args[0]);
        } catch (CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
            System.out.println("Provided PRIVATE_KEY_PATH file "+ args[0] +" does not contain valid X509 Certificate");
            return false;
        }

        byte[] data = getInputBytes(args[1]);
        if (data == null) return false;

        try {
            new FileOutputStream(args[2]).write(decryptData(data, privateKey));
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    private boolean sign(String[] args) {
        if (args.length < 4) {
            return false;
        }
        PrivateKey privateKey;
        try {
            privateKey = loadPrivateKey(args[0]);
        } catch (CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
            System.out.println("Provided PRIVATE_KEY_PATH file "+ args[0] +" does not contain valid X509 Certificate");
            return false;
        }
        X509Certificate x509Certificate;
        try {
            x509Certificate = loadPublicCert(args[1]);
        } catch (CertificateException | NoSuchProviderException | FileNotFoundException e) {
            System.out.println("Provided PUBLIC_CERT_PATH file "+ args[1] +" does not contain valid X509 Certificate");
            return false;
        }

        byte[] data = getInputBytes(args[2]);
        if (data == null) return false;

        try {
            new FileOutputStream(args[3]).write(signData(data, x509Certificate, privateKey));
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    private boolean verify(String[] args) {
        if (args.length < 1) {
            return false;
        }

        byte[] data = getInputBytes(args[0]);
        if (data == null) return false;
        try {
            boolean verifyResult = verifySignedData(data);
            System.out.println("File "+ args[0] +" signature verified " + (verifyResult ? "successfully" : "unsuccessfully"));
        } catch (Exception e) {
            System.out.println("File "+ args[0] +" signature verified unsuccessfully or does not contain signature");
            return false;
        }
        return true;
    }

    private byte[] getInputBytes(String path) {
        byte[] data;
        try {
            data = Files.readAllBytes(Paths.get(path));
        } catch (IOException e) {
            System.out.println("Provided INPUT_FILE_PATH file "+ path +" does not exist");
            return null;
        }
        return data;
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        if (args.length < 2 || args[0].equals("help")) {
            printOutHelp();
            return;
        }
        Lab2 lab2 = new Lab2();
        Function<String[], Boolean> function = lab2.operations.get(args[0]);
        if (function == null) {
            printOutHelp();
            return;
        }
        Boolean success = function.apply(Arrays.copyOfRange(args, 1, args.length));
        if (!success) {
            printOutHelp();
        }
    }

    private static byte[] encryptData(byte[] data, X509Certificate encryptionCertificate) throws CertificateEncodingException, CMSException, IOException {
        byte[] encryptedData = null;
        if (null != data && null != encryptionCertificate) {
            CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();
            JceKeyTransRecipientInfoGenerator jceKey = new JceKeyTransRecipientInfoGenerator(encryptionCertificate);
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(jceKey);

            CMSTypedData msg = new CMSProcessableByteArray(data);
            OutputEncryptor encryptor;
            encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC").build();
            CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(msg, encryptor);
            encryptedData = cmsEnvelopedData.getEncoded();
        }
        return encryptedData;
    }

    private static byte[] decryptData(byte[] encryptedData, PrivateKey decryptionKey) throws CMSException {
        byte[] decryptedData = null;
        if (null != encryptedData && null != decryptionKey) {
            CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);
            Collection<RecipientInformation> recipients = envelopedData.getRecipientInfos().getRecipients();
            KeyTransRecipientInformation recipientInfo = (KeyTransRecipientInformation) recipients.iterator().next();
            JceKeyTransRecipient recipient = new JceKeyTransEnvelopedRecipient(decryptionKey);
            decryptedData = recipientInfo.getContent(recipient);
        }
        return decryptedData;
    }

    private static byte[] signData(byte[] data, X509Certificate signingCertificate, PrivateKey signingKey) throws Exception {
        byte[] signedMessage = null;
        List<X509Certificate> certList = new ArrayList<>();
        CMSTypedData cmsData = new CMSProcessableByteArray(data);
        certList.add(signingCertificate);
        Store certs = new JcaCertStore(certList);
        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
        DigestCalculatorProvider bc = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(bc).build(contentSigner, signingCertificate));
        cmsGenerator.addCertificates(certs);
        CMSSignedData cms = cmsGenerator.generate(cmsData, true);
        signedMessage = cms.getEncoded();
        return signedMessage;
    }

    private static boolean verifySignedData(byte[] signedData) throws Exception {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(signedData);
        ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);
        CMSSignedData cmsSignedData = new CMSSignedData(ContentInfo.getInstance(asnInputStream.readObject()));
        SignerInformationStore signers = cmsSignedData.getSignerInfos();
        SignerInformation signer = signers.getSigners().iterator().next();
        Collection<X509CertificateHolder> certCollection = cmsSignedData.getCertificates().getMatches(signer.getSID());
        X509CertificateHolder certHolder = certCollection.iterator().next();
        return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certHolder));
    }

    private static PrivateKey loadPrivateKey(String privateKeystorePath) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, IOException {
        char[] keystorePassword = "password".toCharArray();
        char[] keyPassword = "password".toCharArray();
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        InputStream privateKeystoreStream = new FileInputStream(privateKeystorePath);
        keystore.load(privateKeystoreStream, keystorePassword);
        return (PrivateKey) keystore.getKey("baeldung", keyPassword);
    }

    private static X509Certificate loadPublicCert(String publicCerPath) throws CertificateException, NoSuchProviderException, FileNotFoundException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
        InputStream publicCerStream = new FileInputStream(publicCerPath);
        return (X509Certificate) certFactory.generateCertificate(publicCerStream);
    }

    private static void printOutHelp() {
        System.out.println();
        System.out.println("Usage: <MODE> [KEY] INPUT_FILE_PATH [OUTPUT_FILE_PATH]");
        System.out.println("MODES:");
        System.out.println("       encrypt PUBLIC_CERT_PATH INPUT_FILE_PATH OUTPUT_FILE_PATH");
        System.out.println("       decrypt PRIVATE_KEY_PATH INPUT_FILE_PATH OUTPUT_FILE_PATH");
        System.out.println("       sign PRIVATE_KEY_PATH PUBLIC_CERT_PATH INPUT_FILE_PATH OUTPUT_FILE_PATH");
        System.out.println("       verify INPUT_FILE_PATH");
    }
}
