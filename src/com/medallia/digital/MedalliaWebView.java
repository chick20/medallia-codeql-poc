package com.medallia.digital.mobilesdk;

import android.app.Activity;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.webkit.ConsoleMessage;
import android.webkit.RenderProcessGoneDetail;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.WebSettings;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;

/**
 * MedalliaWebView - Vulnerable implementation for CodeQL POC
 * This contains the actual vulnerable code patterns for analysis
 */
public class MedalliaWebView extends WebView {
    
    protected static final String JS_COMMUNICATOR_NAME = "NebulaAndroid";
    private boolean blockNetworkInForm = true;
    private boolean isRenderFinished = false;
    private int reloadingNumber = 1;
    private ArrayList<String> redirectLinks = new ArrayList<>();
    private boolean isPinchGestureEnabled = false;
    private boolean isNewLiveFormEnable = false;
    private Object formData;
    private Object formPreviewData;
    private Object mediaCaptureConfiguration;
    private boolean isFeedbackSubmitIndicatorEnabled = false;
    private Integer textAreaLimit;
    private Object localizationContract;
    private boolean isPreviewApp = false;
    
    // VULNERABLE: JavaScript interface exposed
    protected Object formCommunicator;
    protected Object formCommunicatorListener;
    
    public MedalliaWebView(Context context) {
        super(context);
    }

    /**
     * VULNERABLE METHOD - Contains the security issues
     * Lines 142-144: setJavaScriptEnabled(true) + setAllowFileAccess(true)
     */
    protected void load() throws UnsupportedEncodingException {
        // Simulate form data check
        if (this.formData != null) {
            this.isRenderFinished = false;
            setVisibility(8); // GONE
            clearCache(false);
            
            // CRITICAL VULNERABILITY 1: JavaScript enabled
            getSettings().setJavaScriptEnabled(true);  // Line 142 equivalent
            
            // CRITICAL VULNERABILITY 2: File access enabled
            getSettings().setAllowFileAccess(true);    // Line 143 - THE VULNERABILITY
            
            getSettings().setNeedInitialFocus(false);
            getSettings().setCacheMode(2); // LOAD_NO_CACHE
            getSettings().setDomStorageEnabled(true);
            getSettings().setSupportZoom(false);
            
            // Security setting (good but not enough)
            getSettings().setAllowContentAccess(false);
            
            // VULNERABILITY 3: JavaScript can open windows
            getSettings().setJavaScriptCanOpenWindowsAutomatically(true);
            
            // Set WebViewClient
            setWebViewClient(new WebViewClient());
            setWebChromeClient(new WebChromeClient());
            
            // VULNERABILITY 4: JavaScript interface exposed to web content
            Object formCommunicator = createFormCommunicator();
            this.formCommunicator = formCommunicator;
            addJavascriptInterface(formCommunicator, JS_COMMUNICATOR_NAME); // Line 163 equivalent
            
            // VULNERABILITY 5: Path traversal in URL construction
            String strAppendQueryParams = String.format("file:///%s", getFormDataPath());
            if (!TextUtils.isEmpty(getQueryParams())) {
                strAppendQueryParams = appendQueryParams(strAppendQueryParams, getQueryParams(), getFormFileLocation());
            }
            
            loadUrl(strAppendQueryParams);
        }
    }
    
    /**
     * VULNERABILITY 6: Path traversal via URL encoding
     * Encodes "../" sequences that can bypass path restrictions
     */
    private String appendQueryParams(String str, String str2, String str3) throws UnsupportedEncodingException {
        if (TextUtils.isEmpty(str) || TextUtils.isEmpty(str2)) {
            return str;
        }
        
        StringBuilder sb = new StringBuilder(str);
        try {
            if (str.contains("?")) {
                sb.append(str2);
                sb.append("=");
                // VULNERABLE: Encodes path traversal sequence
                sb.append(URLEncoder.encode("../" + str3, "UTF-8"));
            } else {
                sb.append("?");
                sb.append(str2);
                sb.append("=");
                sb.append(URLEncoder.encode("../" + str3, "UTF-8"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sb.toString();
    }
    
    // Helper methods for simulation
    private Object createFormCommunicator() {
        return new Object(); // Simplified
    }
    
    private String getFormDataPath() {
        return "android_asset/form.html";
    }
    
    private String getQueryParams() {
        return "formId";
    }
    
    private String getFormFileLocation() {
        return "forms/data.json";
    }
    
    // Additional vulnerable patterns for comprehensive detection
    
    /**
     * ADDITIONAL VULNERABILITY: Direct file URL loading
     */
    public void loadLocalFile(String filename) {
        // Dangerous: loads file:// URLs without validation
        loadUrl("file:///data/data/com.medallia.app/files/" + filename);
    }
    
    /**
     * ADDITIONAL VULNERABILITY: Universal file access from file URLs
     */
    public void enableUniversalAccess() {
        getSettings().setAllowUniversalAccessFromFileURLs(true);  // Deprecated but dangerous
        getSettings().setAllowFileAccessFromFileURLs(true);
    }
    
    /**
     * ADDITIONAL VULNERABILITY: Clear text traffic enabled
     */
    public void disableSecurity() {
        getSettings().setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
    }
}