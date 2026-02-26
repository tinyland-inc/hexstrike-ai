-- A tool invocation request from an MCP client
let ToolCall =
      { toolName : Text
      , arguments : List { mapKey : Text, mapValue : Text }
      , caller : Text
      , timestamp : Text  -- ISO 8601
      , requestId : Text
      }

in  ToolCall
