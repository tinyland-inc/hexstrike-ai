-- Binary analysis tools
let ToolCapability = ../types/ToolCapability.dhall
let Severity = ../types/Severity.dhall

let disassemble
    : ToolCapability
    = { name = "disassemble"
      , description = "Disassemble binary files to assembly"
      , category = "BinaryAnalysis"
      , requiredBinaries = [ "objdump" ]
      , parameters =
        [ { name = "file", description = "Path to binary file", required = True, paramType = "string" }
        , { name = "symbol", description = "Specific symbol/function to disassemble", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.Low
      , maxExecutionSeconds = 60
      }

let debug
    : ToolCapability
    = { name = "debug"
      , description = "Analyze binaries using GDB in batch mode"
      , category = "BinaryAnalysis"
      , requiredBinaries = [ "gdb" ]
      , parameters =
        [ { name = "file", description = "Path to binary file", required = True, paramType = "string" }
        , { name = "commands", description = "GDB commands (semicolon-separated)", required = False, paramType = "string" }
        , { name = "core", description = "Path to core dump file", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.Medium
      , maxExecutionSeconds = 60
      }

let gadget_search
    : ToolCapability
    = { name = "gadget_search"
      , description = "Search for ROP/JOP gadgets in binaries"
      , category = "BinaryAnalysis"
      , requiredBinaries = [ "ROPgadget" ]
      , parameters =
        [ { name = "file", description = "Path to binary file", required = True, paramType = "string" }
        , { name = "depth", description = "Maximum gadget depth", required = False, paramType = "integer" }
        , { name = "type", description = "Gadget type: rop, jop, sys, all", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.Low
      , maxExecutionSeconds = 120
      }

let firmware_analyze
    : ToolCapability
    = { name = "firmware_analyze"
      , description = "Analyze firmware images for embedded files and signatures"
      , category = "BinaryAnalysis"
      , requiredBinaries = [ "binwalk" ]
      , parameters =
        [ { name = "file", description = "Path to firmware image", required = True, paramType = "string" }
        , { name = "extract", description = "Extract embedded files", required = False, paramType = "boolean" }
        ]
      , riskLevel = Severity.Low
      , maxExecutionSeconds = 300
      }

in  [ disassemble, debug, gadget_search, firmware_analyze ]
