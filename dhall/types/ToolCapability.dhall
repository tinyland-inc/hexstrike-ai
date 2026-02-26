-- A tool capability declaration: what a tool can do, what it needs, how risky it is.
let Severity = ./Severity.dhall

let Parameter =
      { name : Text
      , description : Text
      , required : Bool
      , paramType : Text  -- "string" | "integer" | "boolean"
      }

let ToolCapability =
      { name : Text
      , description : Text
      , category : Text
      , requiredBinaries : List Text
      , parameters : List Parameter
      , riskLevel : Severity
      , maxExecutionSeconds : Natural
      }

in  ToolCapability
