-- Complete compiled policy: grants + denials.
let Grant = ./Grant.dhall

let ToolPolicy =
      { grants : List Grant
      , denied : List Text        -- tools that are always denied
      , version : Text
      }

in  ToolPolicy
