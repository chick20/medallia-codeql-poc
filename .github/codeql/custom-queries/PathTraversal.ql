/**
 * @name Path Traversal in URL Construction
 * @description Detects path traversal sequences in URL encoding
 * @kind problem
 * @problem.severity high
 * @id java/android/webview-path-traversal
 * @tags security
 */

// CodeQL pack: medallia-webview-queries

import java

from MethodCall encode, StringLiteral traversal
where
  encode.getMethod().hasName("encode") and
  encode.getMethod().getDeclaringType().hasName("URLEncoder") and
  traversal.getValue().matches("%../%") and
  encode.getAnArgument() = traversal
select 
  encode, 
  "Path traversal sequence (../) encoded in URL - potential file access bypass"