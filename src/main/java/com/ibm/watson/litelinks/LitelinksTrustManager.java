package com.ibm.watson.litelinks;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static io.netty.util.internal.ObjectUtil.*;

final class LitelinksTrustManager extends X509ExtendedTrustManager {

    private final Set<X509Certificate> x509Certs;
    private final X509TrustManager delegate;

    LitelinksTrustManager(X509TrustManager delegate) {
        this.delegate = checkNotNull(delegate, "delegate");
        this.x509Certs = new HashSet<>(Arrays.asList(delegate.getAcceptedIssuers()));
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String s) throws CertificateException {
        try {
            delegate.checkClientTrusted(chain, s);
        } catch (CertificateException ce) {
            if (chain.length == 0 || !x509Certs.contains(chain[0])) {
                throw ce;
            }
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String s, Socket socket) throws CertificateException {
        delegate.checkClientTrusted(chain, s);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String s, SSLEngine sslEngine)
            throws CertificateException {
        delegate.checkClientTrusted(chain, s);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String s) throws CertificateException {
        delegate.checkServerTrusted(chain, s);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String s, Socket socket)
            throws CertificateException {
        delegate.checkServerTrusted(chain, s);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String s, SSLEngine sslEngine)
            throws CertificateException {
        delegate.checkServerTrusted(chain, s);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }
}