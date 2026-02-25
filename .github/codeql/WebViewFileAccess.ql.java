/**
 * @name Android WebView Insecure File Access
 * @description Detects WebView configurations that enable file access with JavaScript,
 *              leading to arbitrary file theft via XHR requests.
 * @kind path-problem
 * @problem.severity critical
 * @security-severity 9.0
 * @precision high
 * @id java/android/webview-file-access-theft
 * @tags security
 *       external/cwe/cwe-200
 *       external/cwe/cwe-079
 *       external/cwe/cwe-22
 *       medallia
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.android.WebView
import WebViewFileAccessFlow::PathGraph

// Configuration to track WebView settings enabling file access
class WebViewFileAccessConfig extends TaintTracking::Configuration {
  WebViewFileAccessConfig() { this = "WebViewFileAccessConfig" }
  
  // Source: WebSettings object from getSettings()
  override predicate isSource(DataFlow::Node source) {
    exists(MethodCall mc |
      mc.getMethod().hasName("getSettings") and
      mc.getQualifier().getType().(RefType).getASupertype*().hasQualifiedName("android.webkit", "WebView") and
      source.asExpr() = mc
    )
  }
  
  // Sink: setAllowFileAccess(true) calls
  override predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      mc.getMethod().hasName("setAllowFileAccess") and
      mc.getArgument(0).(BooleanLiteral).getBooleanValue() = true and
      sink.asExpr() = mc.getArgument(0)
    )
  }
  
  // Additional step: track through WebSettings variable assignments
  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(VariableAssign va, LocalVariableDecl v |
      va.getSource() = node1.asExpr() and
      va.getDestVar() = v and
      node2.asExpr() = v.getAnAccess()
    )
  }
}

// Detect the specific dangerous pattern: file access + JavaScript enabled
predicate isDangerousWebViewConfiguration(Method m) {
  exists(MethodCall fileAccess, MethodCall jsEnabled |
    // File access enabled
    fileAccess.getMethod().hasName("setAllowFileAccess") and
    fileAccess.getArgument(0).(BooleanLiteral).getBooleanValue() = true and
    fileAccess.getEnclosingCallable() = m and
    
    // JavaScript enabled
    jsEnabled.getMethod().hasName("setJavaScriptEnabled") and
    jsEnabled.getArgument(0).(BooleanLiteral).getBooleanValue() = true and
    jsEnabled.getEnclosingCallable() = m and
    
    // Both in same method
    m.getDeclaringType().getName() = "MedalliaWebView"
  )
}

// Main query: Find vulnerable methods with data flow
from WebViewFileAccessConfig config, DataFlow::PathNode source, DataFlow::PathNode sink, Method m
where
  config.hasFlowPath(source, sink) and
  m = sink.getNode().asExpr().getEnclosingCallable() and
  isDangerousWebViewConfiguration(m)
select 
  sink.getNode(), 
  source, 
  sink, 
  "CRITICAL: MedalliaWebView enables file access ($@) with JavaScript enabled. " +
  "This allows arbitrary file theft via XHR requests from injected JavaScript. " +
  "CVSS: 8.6 (High)",
  sink.getNode(), "setAllowFileAccess(true)"