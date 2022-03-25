package kma.khaipt.timestamp.nc;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPIOException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.util.Store;
import org.bouncycastle.x509.X509Store;

public class Main {
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		PrivateKey privateKey = null;
		X509Certificate cert = null;
		Store certs = null;
		List certList = new ArrayList();
//		String pathFile = "D:/khaipt-tsa.p12";
		String pathFile = "D:/timestamp.p12";
		char[] password = "1".toCharArray();
		try {
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(new FileInputStream(pathFile), password);
			Enumeration<String> aliases = ks.aliases();
			String aliase = null;
			while(aliases.hasMoreElements()) {
				String aliase2 = aliases.nextElement();
				if(ks.isKeyEntry(aliase2)) {
					aliase = aliase2;
				}
			}
			for(Certificate certificate : ks.getCertificateChain(aliase)) {
				certList.add(certificate);
			}
//			System.out.println(certList.size());System.exit(0);
			cert = (X509Certificate) ks.getCertificate(aliase);
			certs = new JcaCertStore(certList);
			privateKey = (PrivateKey) ks.getKey(aliase, password);
//			X509Store x509Store = X509Store.get
		} catch (KeyStoreException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		try {
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(new JcaSimpleSignerInfoGeneratorBuilder().build("SHA1withRSA", privateKey, cert), new SHA1DigestCalculator(), new ASN1ObjectIdentifier("1.2"));
			tsTokenGen.addCertificates(certs);
			
			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			reqGen.addExtension(Extension.biometricInfo, true, new DEROctetString(new byte[20]));
			
			reqGen.setReqPolicy(Extension.noRevAvail);
			TimeStampRequest request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
//			request.validate(new HashSet(), new HashSet(), new HashSet());
			
			Set algorithms = new HashSet();
			algorithms.add(TSPAlgorithms.SHA1);
			
//			request.validate(algorithms, new HashSet(), new HashSet());
			
			Set policies = new HashSet();
		    policies.add(Extension.noRevAvail);
//		    request.validate(algorithms, policies, new HashSet());
		    
		    Set extensions = new HashSet();
		    extensions.add(Extension.biometricInfo);
		    // should validate with full set
		    request.validate(algorithms, policies, extensions);
		    
		    TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);
		    TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date());
		    System.out.println(java.util.Base64.getEncoder().encodeToString(tsResp.getEncoded()));//System.exit(0);
		    tsResp = new TimeStampResponse(tsResp.getEncoded());
		    TimeStampToken tsToken = tsResp.getTimeStampToken();
		    System.out.println(tsToken.getTimeStampInfo().getGenTime());
		    System.out.println(java.util.Base64.getEncoder().encodeToString(tsToken.getTimeStampInfo().getEncoded()));
//		    System.out.println(tsToken.getCertificates().getMatches(null));
		    tsToken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider(new BouncyCastleProvider()).build(cert));
		    AttributeTable table = tsToken.getSignedAttributes();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (TSPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (TSPIOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
