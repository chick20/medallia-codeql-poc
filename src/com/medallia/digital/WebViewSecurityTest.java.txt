package com.medallia.digital.mobilesdk;

import android.content.Context;

/**
 * Test class to demonstrate vulnerable WebView usage
 */
public class WebViewSecurityTest {
    
    public void testVulnerableConfiguration(Context context) throws Exception {
        // Create vulnerable WebView instance
        MedalliaWebView webView = new MedalliaWebView(context);
        
        // This triggers the vulnerable load() method
        webView.load();
        
        // Additional vulnerable calls
        webView.loadLocalFile("sensitive_data.xml");
        webView.enableUniversalAccess();
    }
}