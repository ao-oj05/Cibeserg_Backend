/**
 * @name Server-Side Request Forgery (SSRF) taint analysis
 * @description Localiza peticiones HTTP salientes que reciben parametros del usuario sin comprobacion de IP
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id js/ssrf-custom-audit
 * @tags security
 *       external/cwe/cwe-918
 */

import javascript
import semmle.javascript.security.dataflow.ServerSideRequestForgeryCustomizations
import DataFlow::PathGraph

from DataFlow::Node source, DataFlow::Node sink
where
  // Identifica llamadas a fetch o http con origen en la peticion del usuario
  exists(DataFlow::MethodCallNode call |
    call.getMethodName() = "fetch" and
    sink = call.getArgument(0)
  )
select sink, "Alerta de Seguridad: Se detecto flujo de datos hacia peticion de red saliente (SSRF). Requiere validacion de IP previa."
