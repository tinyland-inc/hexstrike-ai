-- Digital forensics tools
let ToolCapability = ../types/ToolCapability.dhall
let Severity = ../types/Severity.dhall

let memory_forensics
    : ToolCapability
    = { name = "memory_forensics"
      , description = "Analyze memory dumps for processes, network connections, and artifacts"
      , category = "Forensics"
      , requiredBinaries = [ "vol" ]
      , parameters =
        [ { name = "file", description = "Path to memory dump file", required = True, paramType = "string" }
        , { name = "plugin", description = "Volatility plugin: pslist, netscan, filescan, hivelist, hashdump", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.Medium
      , maxExecutionSeconds = 600
      }

let file_carving
    : ToolCapability
    = { name = "file_carving"
      , description = "Recover deleted or embedded files from disk images"
      , category = "Forensics"
      , requiredBinaries = [ "foremost" ]
      , parameters =
        [ { name = "file", description = "Path to disk image or raw file", required = True, paramType = "string" }
        , { name = "types", description = "File types to carve: jpg, png, pdf, doc, exe, all", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.Low
      , maxExecutionSeconds = 600
      }

let steganography
    : ToolCapability
    = { name = "steganography"
      , description = "Detect and extract hidden data in media files"
      , category = "Forensics"
      , requiredBinaries = [ "steghide" ]
      , parameters =
        [ { name = "file", description = "Path to media file", required = True, paramType = "string" }
        , { name = "passphrase", description = "Passphrase for extraction", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.Low
      , maxExecutionSeconds = 60
      }

let metadata_extract
    : ToolCapability
    = { name = "metadata_extract"
      , description = "Extract metadata from files (EXIF, XMP, IPTC, etc.)"
      , category = "Forensics"
      , requiredBinaries = [ "exiftool" ]
      , parameters =
        [ { name = "file", description = "Path to file for metadata extraction", required = True, paramType = "string" }
        ]
      , riskLevel = Severity.Info
      , maxExecutionSeconds = 30
      }

in  [ memory_forensics, file_carving, steganography, metadata_extract ]
