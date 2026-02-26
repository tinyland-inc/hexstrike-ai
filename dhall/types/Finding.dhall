-- A security finding produced by a tool
let Severity = ./Severity.dhall

let Finding =
      { title : Text
      , description : Text
      , severity : Severity
      , toolName : Text
      , target : Text
      , evidence : Text
      , fingerprint : Text         -- SHA-256 of title+target+evidence for dedup
      , recommendation : Text
      , cweId : Optional Text
      , cveId : Optional Text
      }

in  Finding
