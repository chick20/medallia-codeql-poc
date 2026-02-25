/**
 * @name Android WebView Insecure File Access
 * @description Detects WebView configurations that enable file access with JavaScript,
 *              leading to arbitrary file theft via XHR requests.
 * @kind problem
 * @problem.severity critical
 * @security-severity 9.0
 * @precision high
 * @id java/android/webview-file-access-theft
 * @tags security
 *       external/cwe/cwe-200
 *       external/cwe/cwe-079
 *       external/cwe/cwe-22
 */

// Required pack declaration
// CodeQL pack: medallia-webview-queries

import java

// Simple, reliable detection without complex dataflow
// Detects the dangerous pattern: setAllowFileAccess(true)

from MethodCall fileAccess, MethodCall jsEnabled
where
  // File access enabled
  fileAccess.getMethod().hasName("setAllowFileAccess") and
  fileAccess.getArgument(0).(BooleanLiteral).getBooleanValue() = true and
  
  // JavaScript enabled in same method
  jsEnabled.getMethod().hasName("setJavaScriptEnabled") and
  jsEnabled.getArgument(0).(BooleanLiteral).getBooleanValue() = true and
  
  // Both in same callable (method/constructor)
  fileAccess.getEnclosingCallable() = jsEnabled.getEnclosingCallable()
  
select 
  fileAccess, 
  "CRITICAL: WebView enables file access ($@) with JavaScript enabled in $@. " +
  "This allows arbitrary file theft via XHR requests. " +
  "CVSS: 8.6 (High). " +
  "Fix: setAllowFileAccess(false)",
  fileAccess, "setAllowFileAccess(true)",
  jsEnabled.getEnclosingCallable(), jsEnabled.getEnclosingCallable().getName()